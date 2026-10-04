"""
DWE Nessie Infrastructure — Azure Pulumi IaC
Provisions: App Gateway (HTTP→HTTPS) + VMSS + PostgreSQL DB + DNS A record

Two modes:
  - Standalone (default): creates its own App Gateway + public IP
  - Shared LB: attaches to a common-deploy App Gateway backend pool
    (set COMMON_APP_GW_ID + COMMON_APP_GW_PUBLIC_IP in Key Vault)
    Pool ID is derived as {COMMON_APP_GW_ID}/backendAddressPools/nessie-pool

Nessie runs on the VM as two Docker containers:
  - projectnessie/nessie  (internal, port 19120)
  - nginx proxy           (port 19120) — validates Bearer token
"""

import base64
import json
from pathlib import Path

import httpx
import pulumi
import pulumi_azure_native as azure_native
import pulumi_azure_native.dbforpostgresql.v20221201 as pg
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# ─────────────────────────────────────────────────────────────────────────────
# Hydration config
# ─────────────────────────────────────────────────────────────────────────────
_hydration = Path(__file__).parent / "dwe-hydration.yaml"
_dwe = yaml.safe_load(_hydration.read_text()) if _hydration.exists() else {}
if _dwe:
    project_name    = _dwe["project_name"]
    git_repo_url    = _dwe["git_repo_url"]
    adapter_version = _dwe["adapter_version"]
else:
    _cfg            = pulumi.Config()
    project_name    = _cfg.get("project_name") or pulumi.get_project()
    git_repo_url    = _cfg.get("git_repo_url") or ""
    adapter_version = _cfg.get("adapter_version") or "v1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# Stack config
# ─────────────────────────────────────────────────────────────────────────────
config = pulumi.Config()
env                  = config.require("environment")
git_branch           = config.require("git_branch")
secret_id            = config.require("secret_id")
key_vault_name       = config.require("key_vault_name")
azure_location       = config.get("azure_location") or "eastus"
vm_size              = config.get("instance_type") or "Standard_B2s"
volume_size          = int(config.get("volume_size") or "50")
resource_group       = config.require("resource_group")
subscription_id      = config.require("subscription_id")
startup_code_version = config.get("startup_code_version") or ""
app_port             = 19120

suffix         = f"-{env}" if env != "prod" else ""
nessie_db_name = f"nessie_{env}"
tags = {
    "Project":     project_name,
    "ManagedBy":   "Pulumi",
    "Environment": env,
    "GitBranch":   git_branch,
}

# ─────────────────────────────────────────────────────────────────────────────
# Secrets from Azure Key Vault
# ─────────────────────────────────────────────────────────────────────────────
def get_secret(kv_name: str, sid: str) -> dict:
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=f"https://{kv_name}.vault.azure.net/", credential=credential)
    return json.loads(client.get_secret(sid).value)

secrets = get_secret(key_vault_name, secret_id)

vm_subnet_id           = secrets["VM_SUBNET_ID"]
ssh_public_key         = secrets["SSH_PUBLIC_KEY"]
git_deploy_token       = secrets["git_deploy_token"]
git_deploy_username    = secrets.get("git_deploy_username", "x-token-auth")
dns_zone_name          = secrets["DNS_ZONE_NAME"]
dns_record_name        = secrets["DNS_RECORD_NAME"]
dns_zone_rg            = secrets.get("DNS_ZONE_RESOURCE_GROUP", resource_group)
ssl_cert_kv_id         = secrets.get("APP_GW_SSL_CERT_KEY_VAULT_ID", "")

common_app_gw_id        = secrets.get("COMMON_APP_GW_ID", "")
common_app_gw_public_ip = secrets.get("COMMON_APP_GW_PUBLIC_IP", "")
use_common_lb = bool(common_app_gw_id)

if use_common_lb:
    if not common_app_gw_public_ip:
        raise ValueError("COMMON_APP_GW_PUBLIC_IP is required when COMMON_APP_GW_ID is set")
else:
    app_gw_subnet_id = secrets["APP_GW_SUBNET_ID"]

for _key in ("NESSIE_DB_HOST", "NESSIE_DB_PASS", "NESSIE_TOKEN"):
    if not secrets.get(_key):
        raise ValueError(f"Required secret '{_key}' missing from Key Vault secret {secret_id}")

nessie_db_host = secrets["NESSIE_DB_HOST"]
nessie_db_user = secrets.get("NESSIE_DB_USER", "nessie")
nessie_db_pass = secrets["NESSIE_DB_PASS"]

# ─────────────────────────────────────────────────────────────────────────────
# Managed Identity + Key Vault access
# ─────────────────────────────────────────────────────────────────────────────
identity = azure_native.managedidentity.UserAssignedIdentity(
    f"{project_name}-identity{suffix}",
    resource_group_name=resource_group,
    location=azure_location,
    resource_name_=f"{project_name}-identity{suffix}",
    tags=tags,
)

kv_access = azure_native.authorization.RoleAssignment(
    f"{project_name}-kv-role{suffix}",
    scope=pulumi.Output.format(
        "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults/{2}",
        subscription_id, resource_group, key_vault_name,
    ),
    role_definition_id=pulumi.Output.format(
        "/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6",
        subscription_id,
    ),
    principal_id=identity.principal_id,
    principal_type="ServicePrincipal",
)

# ─────────────────────────────────────────────────────────────────────────────
# PostgreSQL database — idempotent (imports if already exists)
# ─────────────────────────────────────────────────────────────────────────────
pg_fqdn_output = pulumi.Output.from_input(nessie_db_host)
_server_name = nessie_db_host.split(".")[0]
_db_res_id = (
    f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    f"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{_server_name}/databases/{nessie_db_name}"
)

def _db_import_id() -> "str | None":
    try:
        token = DefaultAzureCredential().get_token("https://management.azure.com/.default").token
        resp = httpx.get(
            f"https://management.azure.com{_db_res_id}?api-version=2022-12-01",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        return _db_res_id if resp.status_code == 200 else None
    except Exception:
        return None

pg.Database(
    f"{project_name}-pg-db{suffix}",
    resource_group_name=resource_group,
    server_name=_server_name,
    database_name=nessie_db_name,
    opts=pulumi.ResourceOptions(depends_on=[kv_access], import_=_db_import_id()),
)

# ─────────────────────────────────────────────────────────────────────────────
# NSG — port 19120 from VirtualNetwork (covers both App GW subnet and VNet peers)
# ─────────────────────────────────────────────────────────────────────────────
vm_nsg = azure_native.network.NetworkSecurityGroup(
    f"{project_name}-nsg{suffix}",
    resource_group_name=resource_group,
    location=azure_location,
    network_security_group_name=f"{project_name}-nsg{suffix}",
    security_rules=[
        azure_native.network.SecurityRuleArgs(
            name="AllowNessie",
            priority=100, direction="Inbound", access="Allow", protocol="Tcp",
            source_port_range="*", destination_port_range=str(app_port),
            source_address_prefix="VirtualNetwork", destination_address_prefix="*",
        ),
        azure_native.network.SecurityRuleArgs(
            name="AllowSSH",
            priority=110, direction="Inbound", access="Allow", protocol="Tcp",
            source_port_range="*", destination_port_range="22",
            source_address_prefix="VirtualNetwork", destination_address_prefix="*",
        ),
    ],
    tags=tags,
)

# ─────────────────────────────────────────────────────────────────────────────
# Public IP + App Gateway (standalone mode only)
# ─────────────────────────────────────────────────────────────────────────────
public_ip = None
app_gw    = None

if not use_common_lb:
    public_ip = azure_native.network.PublicIPAddress(
        f"{project_name}-pip{suffix}",
        resource_group_name=resource_group,
        location=azure_location,
        public_ip_address_name=f"{project_name}-pip{suffix}",
        sku=azure_native.network.PublicIPAddressSkuArgs(name="Standard"),
        public_ip_allocation_method="Static",
        tags=tags,
    )

    app_gw_name = f"{project_name}-appgw{suffix}"
    ag_prefix = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/applicationGateways/{app_gw_name}"
    )

    ssl_certs = []
    if ssl_cert_kv_id:
        ssl_certs = [azure_native.network.ApplicationGatewaySslCertificateArgs(
            name="tls-cert",
            key_vault_secret_id=ssl_cert_kv_id,
        )]

    has_ssl = bool(ssl_certs)

    http_listeners = [
        azure_native.network.ApplicationGatewayHttpListenerArgs(
            name="http-listener",
            frontend_ip_configuration=azure_native.network.SubResourceArgs(
                id=f"{ag_prefix}/frontendIPConfigurations/appGwPublicFrontendIp"),
            frontend_port=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/frontendPorts/port_80"),
            protocol="Http",
        ),
    ]

    redirect_configurations = []
    if has_ssl:
        http_listeners.append(azure_native.network.ApplicationGatewayHttpListenerArgs(
            name="https-listener",
            frontend_ip_configuration=azure_native.network.SubResourceArgs(
                id=f"{ag_prefix}/frontendIPConfigurations/appGwPublicFrontendIp"),
            frontend_port=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/frontendPorts/port_443"),
            protocol="Https",
            ssl_certificate=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/sslCertificates/tls-cert"),
        ))
        redirect_configurations = [azure_native.network.ApplicationGatewayRedirectConfigurationArgs(
            name="redirect-to-https",
            redirect_type="Permanent",
            target_listener=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/httpListeners/https-listener"),
            include_path=True,
            include_query_string=True,
        )]
        routing_rules = [
            azure_native.network.ApplicationGatewayRequestRoutingRuleArgs(
                name="http-redirect",
                priority=10, rule_type="Basic",
                http_listener=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/httpListeners/http-listener"),
                redirect_configuration=azure_native.network.SubResourceArgs(
                    id=f"{ag_prefix}/redirectConfigurations/redirect-to-https"),
            ),
            azure_native.network.ApplicationGatewayRequestRoutingRuleArgs(
                name="https-route",
                priority=20, rule_type="Basic",
                http_listener=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/httpListeners/https-listener"),
                backend_address_pool=azure_native.network.SubResourceArgs(
                    id=f"{ag_prefix}/backendAddressPools/backendPool"),
                backend_http_settings=azure_native.network.SubResourceArgs(
                    id=f"{ag_prefix}/backendHttpSettingsCollection/backendHttpSettings"),
            ),
        ]
    else:
        routing_rules = [
            azure_native.network.ApplicationGatewayRequestRoutingRuleArgs(
                name="http-route",
                priority=10, rule_type="Basic",
                http_listener=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/httpListeners/http-listener"),
                backend_address_pool=azure_native.network.SubResourceArgs(
                    id=f"{ag_prefix}/backendAddressPools/backendPool"),
                backend_http_settings=azure_native.network.SubResourceArgs(
                    id=f"{ag_prefix}/backendHttpSettingsCollection/backendHttpSettings"),
            )
        ]

    ag_identity = identity.id.apply(lambda iid: azure_native.network.ManagedServiceIdentityArgs(
        type="UserAssigned",
        user_assigned_identities={iid: {}},
    )) if has_ssl else None

    app_gw = azure_native.network.ApplicationGateway(
        app_gw_name,
        resource_group_name=resource_group,
        application_gateway_name=app_gw_name,
        location=azure_location,
        sku=azure_native.network.ApplicationGatewaySkuArgs(name="Standard_v2", tier="Standard_v2", capacity=1),
        identity=ag_identity,
        gateway_ip_configurations=[azure_native.network.ApplicationGatewayIPConfigurationArgs(
            name="appGatewayIpConfig",
            subnet=azure_native.network.SubResourceArgs(id=app_gw_subnet_id),
        )],
        frontend_ip_configurations=[azure_native.network.ApplicationGatewayFrontendIPConfigurationArgs(
            name="appGwPublicFrontendIp",
            public_ip_address=azure_native.network.SubResourceArgs(id=public_ip.id),
        )],
        frontend_ports=[
            azure_native.network.ApplicationGatewayFrontendPortArgs(name="port_80", port=80),
            azure_native.network.ApplicationGatewayFrontendPortArgs(name="port_443", port=443),
        ],
        backend_address_pools=[
            azure_native.network.ApplicationGatewayBackendAddressPoolArgs(name="backendPool"),
        ],
        backend_http_settings_collection=[
            azure_native.network.ApplicationGatewayBackendHttpSettingsArgs(
                name="backendHttpSettings",
                port=app_port, protocol="Http",
                cookie_based_affinity="Disabled",
                request_timeout=60,
                probe=azure_native.network.SubResourceArgs(id=f"{ag_prefix}/probes/healthProbe"),
            )
        ],
        # nginx proxy returns 401 for unauthenticated requests — treat as healthy
        probes=[azure_native.network.ApplicationGatewayProbeArgs(
            name="healthProbe",
            protocol="Http", host="127.0.0.1",
            path="/api/v1/config",
            interval=30, timeout=10, unhealthy_threshold=3,
            match=azure_native.network.ApplicationGatewayProbeHealthResponseMatchArgs(
                status_codes=["200-401"],
            ),
        )],
        http_listeners=http_listeners,
        request_routing_rules=routing_rules,
        ssl_certificates=ssl_certs,
        redirect_configurations=redirect_configurations,
        tags=tags,
        opts=pulumi.ResourceOptions(depends_on=[public_ip, kv_access]),
    )

# ─────────────────────────────────────────────────────────────────────────────
# Startup script
# ─────────────────────────────────────────────────────────────────────────────
def _build_startup_script(pg_fqdn: str) -> str:
    script = f"""#!/bin/bash
set -e
exec > >(tee /var/log/nessie-init.log | logger -t nessie-init) 2>&1

# startup_code_version={startup_code_version}
echo "=== DWE Nessie bootstrap starting ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl gnupg-agent \\
    software-properties-common git jq unzip

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update -y && apt-get install -y docker-ce docker-ce-cli containerd.io
curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" \\
    -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

curl -sL https://aka.ms/InstallAzureCLIDeb | bash

az login --identity
SECRET_JSON=$(az keyvault secret show --vault-name {key_vault_name} --name {secret_id} --query value -o tsv)
GIT_USER=$(echo "$SECRET_JSON" | jq -r '.git_deploy_username // "x-token-auth"')
GIT_TOKEN=$(echo "$SECRET_JSON" | jq -r '.git_deploy_token')
NESSIE_DB_PASS=$(echo "$SECRET_JSON" | jq -r '.NESSIE_DB_PASS')

REPO_URL="{git_repo_url}"
REPO_PATH=$(echo "$REPO_URL" | sed 's,https://,,')
git clone "https://$GIT_USER:$GIT_TOKEN@$REPO_PATH" /home/ubuntu/nessie
git -C /home/ubuntu/nessie checkout {git_branch}

echo "$SECRET_JSON" | jq -r 'to_entries[] | .key + "=" + (.value | tostring)' > /home/ubuntu/nessie/.env
chmod 600 /home/ubuntu/nessie/.env
echo "NESSIE_DB_NAME={nessie_db_name}" >> /home/ubuntu/nessie/.env

chmod +x /home/ubuntu/nessie/nginx/entrypoint.sh

cd /home/ubuntu/nessie
docker-compose -f docker-compose.yml up -d

echo "=== DWE Nessie bootstrap complete ==="
"""
    return base64.b64encode(script.encode()).decode()

nessie_custom_data = pg_fqdn_output.apply(_build_startup_script)

# ─────────────────────────────────────────────────────────────────────────────
# VMSS
# ─────────────────────────────────────────────────────────────────────────────
_backend_pool_id = (
    f"{common_app_gw_id}/backendAddressPools/nessie-pool" if use_common_lb
    else f"{ag_prefix}/backendAddressPools/backendPool"
)

vmss = azure_native.compute.VirtualMachineScaleSet(
    f"{project_name}-vmss{suffix}",
    resource_group_name=resource_group,
    vm_scale_set_name=f"{project_name}-vmss{suffix}",
    location=azure_location,
    sku=azure_native.compute.SkuArgs(name=vm_size, capacity=1, tier="Standard"),
    identity=identity.id.apply(lambda iid: azure_native.compute.VirtualMachineScaleSetIdentityArgs(
        type="UserAssigned",
        user_assigned_identities={iid: {}},
    )),
    upgrade_policy=azure_native.compute.UpgradePolicyArgs(mode="Manual"),
    virtual_machine_profile=azure_native.compute.VirtualMachineScaleSetVMProfileArgs(
        os_profile=azure_native.compute.VirtualMachineScaleSetOSProfileArgs(
            computer_name_prefix=f"{project_name[:9]}ns",
            admin_username="ubuntu",
            linux_configuration=azure_native.compute.LinuxConfigurationArgs(
                disable_password_authentication=True,
                ssh=azure_native.compute.SshConfigurationArgs(
                    public_keys=[azure_native.compute.SshPublicKeyArgs(
                        path="/home/ubuntu/.ssh/authorized_keys",
                        key_data=ssh_public_key,
                    )],
                ),
            ),
            custom_data=nessie_custom_data,
        ),
        storage_profile=azure_native.compute.VirtualMachineScaleSetStorageProfileArgs(
            image_reference=azure_native.compute.ImageReferenceArgs(
                publisher="Canonical",
                offer="0001-com-ubuntu-server-focal",
                sku="20_04-lts-gen2",
                version="latest",
            ),
            os_disk=azure_native.compute.VirtualMachineScaleSetOSDiskArgs(
                create_option="FromImage",
                disk_size_gb=volume_size,
                managed_disk=azure_native.compute.VirtualMachineScaleSetManagedDiskParametersArgs(
                    storage_account_type="Premium_LRS",
                ),
            ),
        ),
        network_profile=azure_native.compute.VirtualMachineScaleSetNetworkProfileArgs(
            network_interface_configurations=[
                azure_native.compute.VirtualMachineScaleSetNetworkConfigurationArgs(
                    name=f"{project_name}-nic{suffix}",
                    primary=True,
                    ip_configurations=[
                        azure_native.compute.VirtualMachineScaleSetIPConfigurationArgs(
                            name=f"{project_name}-ipconfig{suffix}",
                            subnet=azure_native.compute.ApiEntityReferenceArgs(id=vm_subnet_id),
                            application_gateway_backend_address_pools=[
                                azure_native.network.SubResourceArgs(id=_backend_pool_id)
                            ],
                        )
                    ],
                    network_security_group=azure_native.network.SubResourceArgs(id=vm_nsg.id),
                )
            ]
        ),
    ),
    tags=tags,
    opts=pulumi.ResourceOptions(
        depends_on=[app_gw, kv_access] if app_gw else [kv_access],
        replace_on_changes=["virtualMachineProfile"],
        delete_before_replace=True,
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# DNS — A record pointing to App Gateway public IP
# ─────────────────────────────────────────────────────────────────────────────
azure_native.network.RecordSet(
    f"{project_name}-dns{suffix}",
    resource_group_name=dns_zone_rg,
    zone_name=dns_zone_name,
    relative_record_set_name=dns_record_name,
    record_type="A",
    ttl=30,
    a_records=(
        [azure_native.network.ARecordArgs(ipv4_address=common_app_gw_public_ip)]
        if use_common_lb
        else public_ip.ip_address.apply(
            lambda ip: [azure_native.network.ARecordArgs(ipv4_address=ip)] if ip else []
        )
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# KG Phase 2 (optional)
# ─────────────────────────────────────────────────────────────────────────────
_kg_host     = secrets.get("KG_API_HOST", "")
_kg_token    = secrets.get("KG_API_TOKEN", "")
_kg_mappings = _dwe.get("kg_mappings") if _dwe else None

if _kg_host and _kg_token and _kg_mappings:
    import warnings as _warnings
    import httpx as _httpx

    _adapter_name  = _kg_mappings["adapter_name"]
    _kg_props_keys = _kg_mappings.get("kg_adapter_properties", {})
    _kg_outputs    = _kg_mappings.get("kg_pulumi_outputs", {})
    _kg_services   = _kg_mappings.get("services", [])

    _pulumi_export_map = {
        "vmss_name":   vmss.name,
        "appgw_name":  app_gw.name if app_gw else pulumi.Output.from_input(""),
        "url":         pulumi.Output.from_input(f"https://{dns_record_name}.{dns_zone_name}"),
        "environment": pulumi.Output.from_input(env),
    }
    _out_names = list(_kg_outputs.keys())
    _out_vals  = [_pulumi_export_map.get(_kg_outputs[n], pulumi.Output.from_input("")) for n in _out_names]

    def _phase2_hydrate(*resolved):
        props = dict(zip(_out_names, resolved))
        for prop, secret_key in _kg_props_keys.items():
            props[prop] = secrets.get(secret_key, "")
        _headers = {"Authorization": f"Bearer {_kg_token}"}
        _base    = _kg_host.rstrip("/")
        try:
            _httpx.patch(f"{_base}/adapters/{_adapter_name}/{env}", json={"properties": props}, headers=_headers, timeout=10)
        except Exception as _exc:
            _warnings.warn(f"[dwe-kg] PATCH /adapters failed: {_exc}")

    pulumi.Output.all(*_out_vals).apply(_phase2_hydrate)

# ─────────────────────────────────────────────────────────────────────────────
# Outputs
# ─────────────────────────────────────────────────────────────────────────────
pulumi.export("vmss_name",   vmss.name)
pulumi.export("url",         f"https://{dns_record_name}.{dns_zone_name}")
pulumi.export("environment", env)
if app_gw:
    pulumi.export("appgw_name", app_gw.name)
if public_ip:
    pulumi.export("public_ip",  public_ip.ip_address)
