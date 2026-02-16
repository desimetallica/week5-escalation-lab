# week5-escalation-lab
Detect the MITRE ATT&CK T1648 Serverless Execution detection. A complete laboratory.

## Objective
Analyze and deeply understand how privilege escalation via AWS Lambda and iam:PassRole manifests in raw CloudTrail logs — without relying on SIEM, EDR, or automated detections.

This lab focuses on:

- Reconstructing an attack timeline using only CloudTrail data
- Identifying behavioral patterns in API activity
- Recognizing privilege boundary transitions
- Understanding how serverless execution appears from a forensic perspective

The technique aligns with T1648 – Serverless Execution in MITRE ATT&CK.

The goal is to simulate how a cloud security engineer would investigate suspicious IAM behavior using first-principles log analysis. From a blue-team perspective, the key challenge is:

Can we detect the privilege escalation only by reading CloudTrail logs and understanding behavioral patterns?

No prebuilt alerts.
No correlation engine.
No dashboards.
Only structured log analysis.


## Scenario

In this lab environment, the deployed infrastructure consists of a Virtual Private Cloud (VPC) that serves as the foundational network layer for all resources. Within this VPC, there are subnets, route tables, security groups, and EC2 instances configured to simulate a typical cloud workload. The setup includes public-facing components, such as an EC2 instance accessible via SSH and HTTP, and S3 buckets for application data and CloudTrail logs. Security groups define the allowed inbound and outbound traffic, while IAM roles and policies manage user and service permissions. 


### 1. High-privilege Role 


A high-privileged IAM role (`AdminRole`) already exists in the account:

- Trust policy allows assumption by lambda.amazonaws.com
- Attached policy: AdministratorAccess

This role cannot be assumed directly by developers.
It cannot be attached to their identity.
It cannot be managed by them.

However:

It can be passed to Lambda.

### 2. Developer Permissions
We assume that the IAM developers user `bob` has been compromised.

Developers IAM users with limited permissions is misconfigured with:

- `lambda:CreateFunction`
- `lambda:UpdateFunctionConfiguration`
- `lambda:InvokeFunction`
- `iam:PassRole` on `AdminRole`

They cannot:

- Attach policies to themselves
- Modify the AdminRole
- Assume the role directly

On paper, this looks controlled.

In practice, it enables a privilege boundary bypass.

### 3. Escalation Path
A developer can: 
1. Create a Lambda function
2. Specify AdminRole as the execution role
3. Use iam:PassRole to attach it
4. Invoke the function
5. Execute arbitrary AWS administrative API calls

The privilege escalation occurs because: Lambda assumes AdminRole, and Lambda executes attacker-controlled code.

The identity transition becomes:
```Developer IAM User
        ↓
Lambda Invocation
        ↓
AssumedRole: AdminRole
        ↓
AdministratorAccess permissions```

The developer never directly assumes the role — the service does, this is the detection challenge.



## Lab Preparation Steps

1. Prepare your AWS account and credentials (`aws configure`).
2. Generate or use an existing SSH key pair for EC2 access.
3. Edit `terraform/defaults.tfvars` with your AMI ID, region, instance type, and SSH key paths.
4. Initialize and apply Terraform:
   ```sh
   cd terraform
   terraform init
   terraform plan -var-file=terraform/defaults.tfvars
   terraform apply -var-file=terraform/defaults.tfvars
   ```
5. Copy the `ansible_inventory` output from Terraform to `ansible/hosts`.
6. Run the Ansible playbook on ansible folder, check details on ./ansible/README.md
7. Cleanup project:
   ```sh
   terraform destroy -var-file defaults.tfvars
   ```
Serverless computing execution abuse phase:

1. `cd ./config`
2. Zip payload with `zip payload.zip lambda_function.py`.
3. Create a lambda function with aws cli command:
    ```bash
    aws --profile bob lambda create-function \
            --function-name privilege-escalation \
            --runtime python3.12 \
            --handler lambda_function.lambda_handler \
            --role arn:aws:iam::137809406849:role/AdminRole \
            --zip-file fileb://config/payload.zip
    ```
4. Run the lambda: 
    ```bash
    aws --profile bob lambda invoke --function-name privilege-escalation out.json
    ```

## Detection Logic

## Why This Matters

## Lessons Learned