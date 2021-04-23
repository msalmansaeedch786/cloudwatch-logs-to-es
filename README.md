# cloudwatch-logs-to-es

This repo contains everything needed to build, test, and deploy a lambda that indexes CloudWatch logs in Elasticsearch.

## CloudWatch-Logs-To-Elasticsearch Architecture

The CloudWatch-Logs-To-Elasticsearch lambda is automatically fired off when new log data is available in a CloudWatch log group that it is subscribed to.  This makes the log information available for monitoring, alerting, troubleshooting, and debugging in near real-time.  The Lambda also augments the log information with billed duration, memory usage and max memory used.
![CloudWatch-Logs-To-Elasticsearch Architecture](docs/cloudwatch-logs-to-es-architecture.png)

___

## The AWS Serverless Application Model (SAM)

The [AWS Serverless Application Model (SAM)](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/)
is an open-source framework that can be used to build serverless applications on AWS.  SAM is basically an extension of
AWS CloudFormation that makes it very straight forward to develop, debug, build and deploy serverless applications.
SAM provides the following:  

* Single-deployment configuration
* Extension of AWS CloudFormation
* Built-in best practices
* Local debugging and testing

SAM is used in all aspects of the SDLC of this project.

___

## Developer Workstation Set-Up

This project can be maintained and deployed on pretty much any type of developer workstation (Linux, Windows, and macOS) as long as the following are installed:

**Node.js**  
Node.js 10+ is required to perform builds and deployments.  For more information on installing Node.js see [Node.js Downloads](https://nodejs.org/en/download/)

**AWS CLI**  
To use the SAM CLI ensure you have the latest version of the AWS CLI installed and configured on your workstation.  For more information on installing and updating the AWS CLI see [Installing the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)

**SAM CLI**  
The SAM CLI must be installed on your workstation to perform builds and deploys to AWS. For more information see [Installing the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) 

___

## Testing, Building and Deploying the the CloudWatch-Logs-To-Elasticsearch Lambda

Once you have your developer workstation set up as per above, it is quite simple to build, and deploy the CloudWatch-Logs-To-Elasticsearch lambda to AWS.  The only AWS infrastructure prerequisite is a single S3 bucket in your account that is needed to save deployment artifacts to.

You must install the Node.js dependencies before anything else can be done.  From the root of this project, execute the following command:
```sh
npm install
```

Once the Node.js dependencies have been installed you can build, package, and deploy the CloudWatch-Logs-To-Elasticsearch lambda by executing the following command in the root of this project:
```sh
./scripts/deploy-stack.js --env dev --s3-bucket devops --es-endpoint endpoint
```
**REPLACE:**  
 ```dev``` with the name of the Environment (dev, test, staging, prod) you wish to deploy the lambda for  
 ```devops``` with the bucket name for the deployment artifacts  
 ```endpoint``` with the Amazon Elasticsearch endpoint to send the logs to for indexing  

This single command performs the following operations:
 - Source code linting (static analysis)  
 - Code security checks  
 - Building  
 - Packaging  
 - Deployment  

If any operation fails the process will be halted.

___
## Cleanup (Resource Deletion)
To cleanup a deployment, simply execute the following command, this will delete the CloudFormation stack:
```sh
./scripts/delete-stack.js --env dev
```
**REPLACE:**  
 ```dev``` with the name of the Environment (dev, staging, preprod, prod) you wish to delete the stack from.  

This command will completely delete any and all resources from AWS that were created by the CloudWatch-Logs-To-Elasticsearch deployment (deploy-stack.js).

___

## Additional Info
The follow the CI/CD operations are also available as single commands.  
  
Linting and security checks:
```sh
npm run lint
```
Unit tests:
```sh
npm test
```
