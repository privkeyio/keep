import aws_cdk
from aws_cdk import (
    Stack,
    Fn,
    Duration,
    CfnOutput,
    aws_ec2,
    aws_iam,
    aws_ecr,
    aws_autoscaling,
    aws_elasticloadbalancingv2,
    aws_kms,
)
from constructs import Construct


class KeepEnclaveStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        encryption_key = aws_kms.Key(self, "EncryptionKey", enable_key_rotation=True)
        encryption_key.apply_removal_policy(aws_cdk.RemovalPolicy.DESTROY)

        enclave_repo = aws_ecr.Repository.from_repository_name(
            self,
            "KeepEnclaveRepo",
            repository_name="keep-enclave",
        )
        enclave_image_uri = f"{enclave_repo.repository_uri}:latest"

        vpc = aws_ec2.Vpc(
            self,
            "VPC",
            nat_gateways=1,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="public", subnet_type=aws_ec2.SubnetType.PUBLIC
                ),
                aws_ec2.SubnetConfiguration(
                    name="private", subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "KMSEndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.KMS,
            private_dns_enabled=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "ECREndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "ECRDockerEndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            private_dns_enabled=True,
        )

        nitro_sg = aws_ec2.SecurityGroup(
            self,
            "NitroSG",
            vpc=vpc,
            allow_all_outbound=True,
            description="Keep Enclave EC2 security group",
        )

        nitro_sg.add_ingress_rule(
            aws_ec2.Peer.ipv4(vpc.vpc_cidr_block), aws_ec2.Port.tcp(443)
        )
        nitro_sg.add_ingress_rule(
            aws_ec2.Peer.any_ipv4(), aws_ec2.Port.tcp(443), "Allow HTTPS from internet"
        )

        amzn_linux = aws_ec2.MachineImage.latest_amazon_linux2()

        role = aws_iam.Role(
            self,
            "InstanceRole",
            assumed_by=aws_iam.ServicePrincipal("ec2.amazonaws.com"),
        )
        role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )

        encryption_key.grant_encrypt_decrypt(role)
        enclave_repo.grant_pull(role)

        block_device = aws_ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=aws_ec2.BlockDeviceVolume(
                ebs_device=aws_ec2.EbsDeviceProps(
                    volume_size=32,
                    volume_type=aws_ec2.EbsDeviceVolumeType.GP3,
                    encrypted=True,
                    delete_on_termination=True,
                )
            ),
        )

        mappings = {
            "__ENCLAVE_IMAGE_URI__": enclave_image_uri,
            "__REGION__": self.region,
            "__KMS_KEY_ID__": encryption_key.key_id,
        }

        with open("user_data.sh") as f:
            user_data_raw = Fn.sub(f.read(), mappings)

        launch_template = aws_ec2.LaunchTemplate(
            self,
            "LaunchTemplate",
            instance_type=aws_ec2.InstanceType("m6i.xlarge"),
            user_data=aws_ec2.UserData.custom(user_data_raw),
            nitro_enclave_enabled=True,
            machine_image=amzn_linux,
            block_devices=[block_device],
            role=role,
            http_put_response_hop_limit=2,
            key_name="keep-enclave",
        )

        # Configure network interface with public IP and security group
        cfn_launch_template = launch_template.node.default_child
        cfn_launch_template.add_property_override(
            "LaunchTemplateData.NetworkInterfaces",
            [
                {
                    "DeviceIndex": 0,
                    "AssociatePublicIpAddress": True,
                    "Groups": [nitro_sg.security_group_id],
                }
            ],
        )

        nlb = aws_elasticloadbalancingv2.NetworkLoadBalancer(
            self,
            "NLB",
            internet_facing=False,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
        )

        asg = aws_autoscaling.AutoScalingGroup(
            self,
            "ASG",
            max_capacity=2,
            min_capacity=1,
            launch_template=launch_template,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PUBLIC
            ),
            update_policy=aws_autoscaling.UpdatePolicy.rolling_update(),
        )

        nlb.add_listener(
            "Listener",
            port=443,
            protocol=aws_elasticloadbalancingv2.Protocol.TCP,
            default_target_groups=[
                aws_elasticloadbalancingv2.NetworkTargetGroup(
                    self,
                    "TargetGroup",
                    targets=[asg],
                    protocol=aws_elasticloadbalancingv2.Protocol.TCP,
                    port=443,
                    vpc=vpc,
                )
            ],
        )

        CfnOutput(self, "InstanceRoleArn", value=role.role_arn)
        CfnOutput(self, "KMSKeyId", value=encryption_key.key_id)
        CfnOutput(self, "KMSKeyArn", value=encryption_key.key_arn)
        CfnOutput(self, "NLBDns", value=nlb.load_balancer_dns_name)
        CfnOutput(self, "ASGName", value=asg.auto_scaling_group_name)
