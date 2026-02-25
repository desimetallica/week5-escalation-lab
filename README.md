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

The detection goal is to reconstruct the escalation using raw CloudTrail events. The escalation chain typically appears in CloudTrail as:

1. PassRole
2. CreateFunction
3. InvokeFunction
4. Administrative API calls under AssumedRole

Even without correlation tooling, a timeline-based analysis reveals:

- Delegation
- Service-mediated role assumption
- Privilege boundary crossing

This sequence is the detection anchor. The detection goal is to reconstruct the escalation using raw CloudTrail events. 

### 1. Detect Role Delegation

In AWS, `iam:PassRole` does not generate a separate CloudTrail event. When a developer creates or updates a Lambda function with a role they are allowed to pass, the PassRole permission is only checked internally by AWS. CloudTrail logs the Lambda API call (`CreateFunction` or `UpdateFunctionConfiguration`) but not the PassRole action itself.

From a blue-team perspective, this means detection must focus on Lambda creation or update events where the execution role is a sensitive role, such as `AdminRole`.

``` bash
jq '.Records[] |
    select(.eventName? // "" | test("Update|CreateFunction")) |
    {
        time: .eventTime,
        user: .userIdentity.arn,
        lambda: .requestParameters.functionName,
        role: .requestParameters.role,
        source_ip: .sourceIPAddress,
        event_id: .eventID
    }' *.json

{
  "time": "2026-02-18T15:06:53Z",
  "user": "arn:aws:iam::137809406849:user/bob",
  "lambda": "privilege-escalation",
  "role": "arn:aws:iam::137809406849:role/AdminRole",
  "source_ip": "93.51.116.45",
  "event_id": "a9665076-a3da-45b3-961f-47d682c5f5ed"
}
```
### 3. Detect Lambda-Initiated Assume Role Events Pivot
This detects when Lambda assumes *any* role: 

``` json
jq '.Records[] |
    select(.eventSource == "sts.amazonaws.com") |
    select(.eventName == "AssumeRole") |
    select(.userIdentity.invokedBy? == "lambda.amazonaws.com") |
    {
        time: .eventTime,
        role_arn: .requestParameters.roleArn,
        session_name: .requestParameters.roleSessionName,
        account: .recipientAccountId
    }' *.json
```

This gives you:
- When the role was assumed
- Which role
- Under what session name
- By Lambda

This is the **pivot detection baseline**.

### 4. Considerations on real case Lambda-Based Privilege Escalation

While explicit IAM modifications such as `AttachUserPolicy` with `AdministratorAccess` are easy to detect, a realistic attacker will often avoid noisy privilege-escalation patterns. Instead, they may leverage a Lambda function configured with an already-privileged execution role and perform sensitive actions without modifying IAM at all.

A stealthier real case scenario approach may include:

- Using the assumed role to access sensitive resources (S3, Secrets Manager, EC2) without changing IAM policies.
- Creating minimal inline policies instead of attaching well-known managed policies.
- Generating access keys for existing privileged users.
- Modifying role trust policies instead of attaching policies.
- Embedding malicious logic inside legitimate automation Lambda functions.
- Executing once and deleting the function immediately after use.

In these cases, no obvious `AttachUserPolicy` or `PutUserPolicy` event may appear. The only consistent pivot point is the `AssumeRole` event initiated by the Lambda service **AND** the role has high privilege.

A more reliable detection focus therefor on:

- Monitoring AssumeRole events where invokedBy is lambda.amazonaws.com.
- Correlating assumed-role sessions with high-privilege roles.
- Detecting any IAM API calls originating from credentials issued to a Lambda function.
- Alerting on modifications to CloudTrail, CloudWatch Logs, or log retention settings.
- Investigating Lambda functions that assume privileged roles but perform minimal visible actions.

## Why This Matters

## Lessons Learned