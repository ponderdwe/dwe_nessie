"""
DWE Nessie Infrastructure — Azure Pulumi IaC
Provisions: PostgreSQL DB (in existing cluster) + VMSS (single instance)

Nessie runs on the VM as two Docker containers:
  - projectnessie/nessie  (internal, port 19120)
  - nginx proxy           (public port 19120) — validates Bearer token
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

vm_subnet_id        = secrets["VM_SUBNET_ID"]
ssh_public_key      = secrets["SSH_PUBLIC_KEY"]
git_deploy_token    = secrets["git_deploy_token"]
git_deploy_username = secrets.get("git_deploy_username", "x-token-auth")

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
# PostgreSQL database for Nessie metadata
# Uses import_ to adopt the DB if it already exists in Azure (idempotent).
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
# NSG — allow port 19120 (Nessie/nginx proxy) from internet, SSH from VNet
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
            source_port_range="*", destination_port_range="19120",
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
echo "QUARKUS_DATASOURCE_JDBC_URL=jdbc:postgresql://{pg_fqdn}:5432/{nessie_db_name}" >> /home/ubuntu/nessie/.env
echo "QUARKUS_DATASOURCE_USERNAME={nessie_db_user}" >> /home/ubuntu/nessie/.env
echo "QUARKUS_DATASOURCE_PASSWORD=$NESSIE_DB_PASS" >> /home/ubuntu/nessie/.env

chmod +x /home/ubuntu/nessie/nginx/entrypoint.sh

cd /home/ubuntu/nessie
docker-compose -f docker-compose.yml up -d

echo "=== DWE Nessie bootstrap complete ==="
"""
    return base64.b64encode(script.encode()).decode()

nessie_custom_data = pg_fqdn_output.apply(_build_startup_script)

# ─────────────────────────────────────────────────────────────────────────────
# VMSS (single instance — Trino reaches Nessie on port 19120 via VNet private IP)
# ─────────────────────────────────────────────────────────────────────────────
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
                        )
                    ],
                    network_security_group=azure_native.network.SubResourceArgs(id=vm_nsg.id),
                )
            ]
        ),
    ),
    tags=tags,
    opts=pulumi.ResourceOptions(
        depends_on=[kv_access],
        replace_on_changes=["virtualMachineProfile"],
        delete_before_replace=True,
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# KG Phase 2 (optional)
# ─────────────────────────────────────────────────────────────────────────────
_kg_host     = secrets.get("KG_API_HOST", "")
_kg_token    = secrets.get("KG_API_TOKEN", "")
_kg_mappings = _dwe.get("kg_mappings") if _dwe else None

if _kg_host and _kg_token and _kg_mappings:
    import httpx as _httpx
    import warnings as _warnings

    _adapter_name  = _kg_mappings["adapter_name"]
    _kg_props_keys = _kg_mappings.get("kg_adapter_properties", {})
    _kg_outputs    = _kg_mappings.get("kg_pulumi_outputs", {})
    _kg_services   = _kg_mappings.get("services", [])

    _pulumi_export_map = {
        "vmss_name":   vmss.name,
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
pulumi.export("environment", env)
# Retrieve the VM private IP after deploy:
# az vmss nic list --resource-group <rg> --vmss-name <vmss_name> --query "[0].ipConfigurations[0].privateIPAddress" -o tsv
# Then set CATALOG_URL=http://<private-ip>:19120 in the Trino secret.
