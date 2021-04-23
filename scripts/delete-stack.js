#!/usr/bin/env node
/* eslint-disable node/shebang */
/* eslint-disable security/detect-child-process */
/* eslint-disable no-process-exit */

const { execSync } = require('child_process');
const commander = require('commander');
const appPackage = require('../package.json');

let stackName = appPackage.name;
let defaultProfile = process.env.AWS_PROFILE || 'default';
commander
    .description(`Deletes the ${stackName} CloudFormation stack.`)
    .version(appPackage.version, '-v, --version', 'output the current version')
    .option('-e, --env <environment>', 'Environment to deploy to.', process.env.ENV)
    .option('-p, --profile <AWS profile>', 'Name of the AWS CLI profile to use with the script, default="default".', defaultProfile)
    .parse(process.argv);

// If no environment was provided print the usage and exit
if (!commander.env) {
    console.error('\nERROR: --env option or ENV environment variable are required!\n');
    commander.description(null);
    commander.outputHelp();
    process.exit(1);
}

// Executes the command. If error occurs outputs the error message and exits with error code.
function exec(args, errorMessage) {
    try {
        let commandLine = args.join(' ');
        execSync(commandLine);
    } catch(err) {
        if (errorMessage) {
            console.error(`\n${errorMessage}\n`);
        } else {
            console.error('\n');
        }
        process.exit(err.code);
    }
}

// Make sure the stack exists
stackName = `${stackName}-${commander.env}`;
exec(['aws', 'cloudformation', 'describe-stacks', '--stack-name', stackName, '--profile', commander.profile], null);

// Use CloudFormation to delete the stack
exec(['aws', 'cloudformation', 'delete-stack', '--stack-name', stackName,
    '--profile', commander.profile], 'Delete stack failed!');
console.log(`\nThe ${stackName} stack is being deleted, this may take several minutes.\n`);