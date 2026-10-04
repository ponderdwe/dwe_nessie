"""
DWE Nessie Infrastructure — AWS Pulumi IaC
Provisions: IAM role + Security Groups + EC2 (ASG min=max=1)

Nessie runs on the EC2 instance as two Docker containers:
  - projectnessie/nessie  (internal, port 19120)
  - nginx proxy           (public port 19120) — validates Bearer token
"""

import base64
import json
from pathlib import Path

import boto3
import pulumi
import pulumi_aws as aws
import yaml

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
instance_type        = config.get("instance_type") or "t3.small"
volume_size          = int(config.get("volume_size") or "50")
aws_region           = config.get("aws_region") or "us-east-1"
startup_code_version = config.get("startup_code_version") or ""

suffix = f"-{env}" if env != "prod" else ""
nessie_db_name = f"nessie_{env}"
tags = {
    "Project":     project_name,
    "ManagedBy":   "Pulumi",
    "Environment": env,
    "GitBranch":   git_branch,
}

# ─────────────────────────────────────────────────────────────────────────────
# Secrets from AWS Secrets Manager
# ─────────────────────────────────────────────────────────────────────────────
def get_secret(sid: str) -> dict:
    client = boto3.client("secretsmanager", region_name=aws_region)
    return json.loads(client.get_secret_value(SecretId=sid)["SecretString"])

secrets = get_secret(secret_id)

vpc_id        = secrets["VPC_ID"]
subnet_ids    = json.loads(secrets["SUBNET_IDS"])
key_name      = secrets.get("KEY_NAME", "")
git_deploy_token    = secrets["git_deploy_token"]
git_deploy_username = secrets.get("git_deploy_username", "x-token-auth")

for _key in ("NESSIE_DB_HOST", "NESSIE_DB_PASS", "NESSIE_TOKEN"):
    if not secrets.get(_key):
        raise ValueError(f"Required secret '{_key}' missing from Secrets Manager secret {secret_id}")

nessie_db_host = secrets["NESSIE_DB_HOST"]
nessie_db_user = secrets.get("NESSIE_DB_USER", "nessie")
nessie_db_pass = secrets["NESSIE_DB_PASS"]

# ─────────────────────────────────────────────────────────────────────────────
# IAM
# ─────────────────────────────────────────────────────────────────────────────
instance_role = aws.iam.Role(
    f"{project_name}-role{suffix}",
    name=f"{project_name}-role{suffix}",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }),
    tags=tags,
)
aws.iam.RolePolicyAttachment(f"{project_name}-ssm{suffix}", role=instance_role.name, policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
aws.iam.RolePolicyAttachment(f"{project_name}-sm{suffix}",  role=instance_role.name, policy_arn="arn:aws:iam::aws:policy/SecretsManagerReadWrite")

instance_profile = aws.iam.InstanceProfile(
    f"{project_name}-profile{suffix}", name=f"{project_name}-profile{suffix}",
    role=instance_role.name, tags=tags,
)

# ─────────────────────────────────────────────────────────────────────────────
# Security group — port 19120 public, SSH from VPC
# ─────────────────────────────────────────────────────────────────────────────
vpc_info = aws.ec2.get_vpc(id=vpc_id)

ec2_sg = aws.ec2.SecurityGroup(
    f"{project_name}-sg{suffix}",
    name=f"{project_name}-sg{suffix}",
    description="Nessie EC2",
    vpc_id=vpc_id,
    tags={**tags, "Name": f"{project_name}-sg{suffix}"},
)
aws.ec2.SecurityGroupRule(f"{project_name}-nessie{suffix}",
    type="ingress", security_group_id=ec2_sg.id,
    protocol="tcp", from_port=19120, to_port=19120, cidr_blocks=["0.0.0.0/0"])
aws.ec2.SecurityGroupRule(f"{project_name}-ssh{suffix}",
    type="ingress", security_group_id=ec2_sg.id,
    protocol="tcp", from_port=22, to_port=22, cidr_blocks=[vpc_info.cidr_block])
aws.ec2.SecurityGroupRule(f"{project_name}-egress{suffix}",
    type="egress", security_group_id=ec2_sg.id,
    protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])

# ─────────────────────────────────────────────────────────────────────────────
# AMI — Ubuntu 20.04 LTS
# ─────────────────────────────────────────────────────────────────────────────
ubuntu_ami = aws.ec2.get_ami(
    most_recent=True,
    filters=[
        aws.ec2.GetAmiFilterArgs(name="name",               values=["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]),
        aws.ec2.GetAmiFilterArgs(name="virtualization-type", values=["hvm"]),
    ],
    owners=["099720109477"],
)

# ─────────────────────────────────────────────────────────────────────────────
# User data
# ─────────────────────────────────────────────────────────────────────────────
_user_data_script = f"""#!/bin/bash
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

curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp && /tmp/aws/install

SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id {secret_id} --region {aws_region} --query SecretString --output text)
GIT_USER=$(echo "$SECRET_JSON" | jq -r '.git_deploy_username // "x-token-auth"')
GIT_TOKEN=$(echo "$SECRET_JSON" | jq -r '.git_deploy_token')
NESSIE_DB_PASS=$(echo "$SECRET_JSON" | jq -r '.NESSIE_DB_PASS')
NESSIE_DB_HOST=$(echo "$SECRET_JSON" | jq -r '.NESSIE_DB_HOST')
NESSIE_DB_USER=$(echo "$SECRET_JSON" | jq -r '.NESSIE_DB_USER // "nessie"')

REPO_URL="{git_repo_url}"
REPO_PATH=$(echo "$REPO_URL" | sed 's,https://,,')
git clone "https://$GIT_USER:$GIT_TOKEN@$REPO_PATH" /home/ubuntu/nessie
git -C /home/ubuntu/nessie checkout {git_branch}

apt-get install -y postgresql-client
PGPASSWORD="$NESSIE_DB_PASS" psql -h "$NESSIE_DB_HOST" -U "$NESSIE_DB_USER" -d postgres \\
    -c "CREATE DATABASE {nessie_db_name};" 2>/dev/null || true

echo "$SECRET_JSON" | jq -r 'to_entries[] | .key + "=" + (.value | tostring)' > /home/ubuntu/nessie/.env
chmod 600 /home/ubuntu/nessie/.env
echo "QUARKUS_DATASOURCE_JDBC_URL=jdbc:postgresql://$NESSIE_DB_HOST:5432/{nessie_db_name}" >> /home/ubuntu/nessie/.env
echo "QUARKUS_DATASOURCE_USERNAME=$NESSIE_DB_USER" >> /home/ubuntu/nessie/.env
echo "QUARKUS_DATASOURCE_PASSWORD=$NESSIE_DB_PASS" >> /home/ubuntu/nessie/.env

chmod +x /home/ubuntu/nessie/nginx/entrypoint.sh

cd /home/ubuntu/nessie
docker-compose -f docker-compose.yml up -d

echo "=== DWE Nessie bootstrap complete ==="
"""
user_data = base64.b64encode(_user_data_script.encode()).decode()

# ─────────────────────────────────────────────────────────────────────────────
# Launch Template + ASG
# ─────────────────────────────────────────────────────────────────────────────
lt = aws.ec2.LaunchTemplate(
    f"{project_name}-lt{suffix}",
    name_prefix=f"{project_name}{suffix}-",
    image_id=ubuntu_ami.id,
    instance_type=instance_type,
    key_name=key_name or None,
    vpc_security_group_ids=[ec2_sg.id],
    iam_instance_profile=aws.ec2.LaunchTemplateIamInstanceProfileArgs(name=instance_profile.name),
    block_device_mappings=[aws.ec2.LaunchTemplateBlockDeviceMappingArgs(
        device_name="/dev/sda1",
        ebs=aws.ec2.LaunchTemplateBlockDeviceMappingEbsArgs(
            volume_size=volume_size, volume_type="gp2",
            encrypted=True, delete_on_termination=True,
        ),
    )],
    user_data=user_data,
    tag_specifications=[aws.ec2.LaunchTemplateTagSpecificationArgs(
        resource_type="instance",
        tags={**tags, "Name": f"nessie{suffix}"},
    )],
    tags=tags,
)

asg = aws.autoscaling.Group(
    f"{project_name}-asg{suffix}",
    name=f"{project_name}-asg{suffix}",
    min_size=1, max_size=1, desired_capacity=1,
    vpc_zone_identifiers=subnet_ids,
    launch_template=aws.autoscaling.GroupLaunchTemplateArgs(id=lt.id, version="$Latest"),
    health_check_type="EC2",
    health_check_grace_period=300,
    instance_refresh=aws.autoscaling.GroupInstanceRefreshArgs(
        strategy="Rolling",
        preferences=aws.autoscaling.GroupInstanceRefreshPreferencesArgs(
            min_healthy_percentage=0,
            instance_warmup=300,
        ),
    ),
    tags=[aws.autoscaling.GroupTagArgs(key=k, value=v, propagate_at_launch=True) for k, v in {**tags, "Name": f"nessie{suffix}"}.items()],
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

    _pulumi_export_map = {"asg_name": asg.name}
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
pulumi.export("asg_name",    asg.name)
pulumi.export("environment", env)
# After deploy, get the EC2 public IP:
# aws ec2 describe-instances --filters "Name=tag:aws:autoscaling:groupName,Values=<asg_name>" \
#   --query "Reservations[0].Instances[0].PublicIpAddress" --output text
# Then set CATALOG_URL=http://<ip>:19120 in the Trino secret.
