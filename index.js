'use strict';
/* eslint-disable security/detect-object-injection */

const https = require('https');
const crypto = require('crypto');
const zlib = require('zlib');

// Get the lambda logger and enable log.debug ()
const log = require('lambda-log');
log.options.debug = process.env.LOG_DEBUG === 'true' || false;

/*
 * Get the Elasticsearch Endpoint from the environment.
 */
const esEndpoint = process.env.ES_ENDPOINT;

exports.handler = function(event, context) {
    processAwsLogsData(event, context);
};

function processAwsLogsData(event, context) {

    // decode input from base64
    var zippedInput = new Buffer.from(event.awslogs.data, 'base64');

    // decompress the input
    zlib.gunzip(zippedInput, function(error, buffer) {
        if (error) {
            log.error({ message: 'Error unzipping AWS log data', error: error.message });
            context.fail(error);
            return;
        }

        // parse the input from JSON
        var awslogsData = JSON.parse(buffer.toString('utf8'));

        // Sometimes CloudWatch Logs may emit Kinesis records with a "CONTROL_MESSAGE" type,
        // mainly for checking if the destination is reachable. If it is we are done here.
        if (awslogsData.messageType === 'CONTROL_MESSAGE') {
            log.info({ message: 'Received a control message' });
            context.succeed('Control message handled successfully');
            return;
        }

        // We have a "DATA_MESSAGE", process it
        // Transform the AWS logs data to Elasticsearch documents
        var elasticsearchBulkData = transformToElasticsearch(awslogsData);

        // post documents to the Amazon Elasticsearch Service
        post(elasticsearchBulkData, function(error, results, statusCode, failedItems) {

            if (error) {

                log.error({
                    message: 'Errors sending logs to Elasticsearch',
                    statusCode: statusCode,
                    logGroup: awslogsData.logGroup,
                    logStream: awslogsData.logStream,
                    results: results
                });

                if (log.options.debug && failedItems && failedItems.length > 0) {
                    log.debug({
                        logGroup: awslogsData.logGroup,
                        logStream: awslogsData.logStream,
                        failedItems: failedItems
                    });
                }

            } else {
                log.info({ message:
                    'Successfully sent logs to Elasticsearch',
                    statusCode: statusCode,
                    logGroup: awslogsData.logGroup,
                    logStream: awslogsData.logStream,
                    results: results
                });
                context.succeed('Success');
            }
        });
    });
}

function transformToElasticsearch(payload) {

    if (payload.messageType === 'CONTROL_MESSAGE') {
        return null;
    }

    log.info({
        message: 'Processing CloudWatch log data',
        logGroup: payload.logGroup,
        logStream: payload.logStream,
        owner: payload.owner
    });

    var bulkRequestBody = '';
    payload.logEvents.forEach(function(logEvent) {
        var timestamp = new Date(1 * logEvent.timestamp);

        // index name format: '{aws-service}-logs-YYYY.MM.DD'
        // Where {aws-service} is pulled from the log group name, i.e. 'lambda', 'aes', 'ec2', ...
        var parts = payload.logGroup.split('/');
        var service = (parts.length > 3 && parts[1] == 'aws') ? parts[2] :
            (payload.logGroup.endsWith('fargate') ? 'fargate' : 'cloudwatch');
        var resource = (parts.length > 3 && parts[1] == 'aws') ? parts.slice(3, parts.length).join('/') : null;
        var indexName = [
            service + '-logs-' + timestamp.getUTCFullYear(), // prefix + year
            ('0' + (timestamp.getUTCMonth() + 1)).slice(-2), // month
            ('0' + timestamp.getUTCDate()).slice(-2)         // day
        ].join('.');

        var source = buildSource(logEvent, service, resource);
        source['@timestamp'] = new Date(1 * logEvent.timestamp).toISOString();
        source['@message'] = logEvent.message;
        source['@owner'] = payload.owner;
        source['@log_group'] = payload.logGroup;

        var action = { index: {} };
        action.index._index = indexName;
        action.index._type = 'cloudwatch-logs';
        action.index._id = logEvent.id;
        
        bulkRequestBody += [ 
            JSON.stringify(action), 
            JSON.stringify(source),
        ].join('\n') + '\n';
    });

    return bulkRequestBody;
}

function buildSource(logEvent, service, resource) {

    var message = logEvent.message;
    var extractedFields = logEvent.extractedFields;
    var source = {};
    if (extractedFields) {

        for (var key in extractedFields) {
            if (extractedFields.hasOwnProperty(key) && extractedFields[key]) {
                var value = extractedFields[key];

                if (isNumeric(value)) {
                    source[key] = 1 * value;
                    continue;
                }

                var jsonSubString = extractJson(value);
                if (jsonSubString !== null) {
                    source['$' + key] = JSON.parse(jsonSubString);
                }

                source[key] = value;
            }
        }

        return source;
    }

    jsonSubString = extractJson(message);
    if (jsonSubString !== null) { 
        return JSON.parse(jsonSubString); 
    }

    // If the log group belongs to a lambda and the message contains 'Request Id:' it most likely is
    // a Lambda START, END, or REPORT message, if so, pull some useful info out of it.
    if (service === 'lambda' && message && message.includes(' RequestId:')) {

        var lambda = {};
        var parts = message.split('\t');
        if (parts[0].startsWith('REPORT ') && parts.length > 4) {
            lambda.eventType = 'REPORT';
            lambda.duration = parseFloat(parts[1].substring('Duration:'.length));
            lambda.billedDuration = parseFloat(parts[2].substring('Billed Duration:'.length));
            lambda.memorySize = parseFloat(parts[3].substring('Memory Size:'.length));
            lambda.maxMemoryUsed = parseFloat(parts[4].substring('Max Memory Used:'.length));
        } else if (parts[0].startsWith('START ')) {
            lambda.eventType = 'START';
            lambda.version = parts[0].substring(parts[0].indexOf('Version:') + 8).trim();
        } else if (parts[0].startsWith('END ')) {
            lambda.eventType = 'END';
        } else {
            return {};
        }

        lambda.name = resource;
        lambda.requestId = parts[0].substring(message.indexOf('RequestId:') + 10).trim();
        source['@lambda'] = lambda;
        return source;
    }

    return {};
}

function extractJson(message) {
    var jsonStart = message.indexOf('{');
    if (jsonStart < 0) return null;
    var jsonSubString = message.substring(jsonStart);
    return isValidJson(jsonSubString) ? jsonSubString : null;
}

function isValidJson(message) {
    try {
        JSON.parse(message);
    } catch (e) { return false; }
    return true;
}

function isNumeric(n) {
    return !isNaN(parseFloat(n)) && isFinite(n);
}

function post(body, callback) {
    var requestParams = buildRequest(esEndpoint, body);

    var request = https.request(requestParams, function(response) {
        var responseBody = '';
        response.on('data', function(chunk) {
            responseBody += chunk;
        });

        response.on('end', function() {
            var info = JSON.parse(responseBody);
            var failedItems = {};
            var results = {};
            var error = null;

            if (info.items) {
                failedItems = info.items.filter(function(x) {
                    return x.index.status >= 300;
                });

                results = { 
                    "attemptedItems": info.items.length,
                    "successfulItems": info.items.length - failedItems.length,
                    "failedItems": failedItems.length
                };
            }

            if (response.statusCode !== 200 || info.errors === true) {
                // prevents logging of failed entries, but allows logging 
                // of other errors such as access restrictions
                delete info.items;
                error = {
                    responseBody: info
                };
            }

            callback(error, results, response.statusCode, failedItems);
        });
    }).on('error', function(e) {
        callback(e);
    });

    request.end(requestParams.body);
}

function buildRequest(endpoint, body) {

    var host = (endpoint.startsWith('https://') ? endpoint.substring(8) : endpoint);
    var endpointParts = endpoint.match(/^([^.]+)\.?([^.]*)\.?([^.]*)\.amazonaws\.com$/);
    var region = '';
    var service = '';
    if (endpointParts && endpointParts.length > 3) {
        region = endpointParts[2];
        service = endpointParts[3];
    }

    var datetime = (new Date()).toISOString().replace(/[:-]|\.\d{3}/g, '');
    var date = datetime.substr(0, 8);
    var kDate = hmac('AWS4' + process.env.AWS_SECRET_ACCESS_KEY, date);
    var kRegion = hmac(kDate, region);
    var kService = hmac(kRegion, service);
    var kSigning = hmac(kService, 'aws4_request');
    
    var request = {
        host: host,
        method: 'POST',
        path: '/_bulk',
        body: body,
        headers: { 
            'Content-Type': 'application/json',
            'Host': host,
            'Content-Length': Buffer.byteLength(body),
            'X-Amz-Security-Token': process.env.AWS_SESSION_TOKEN,
            'X-Amz-Date': datetime
        }
    };

    var canonicalHeaders = Object.keys(request.headers)
        .sort(function(a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; })
        .map(function(k) { return k.toLowerCase() + ':' + request.headers[k]; })
        .join('\n');

    var signedHeaders = Object.keys(request.headers)
        .map(function(k) { return k.toLowerCase(); })
        .sort()
        .join(';');

    var canonicalString = [
        request.method,
        request.path, '',
        canonicalHeaders, '',
        signedHeaders,
        hash(request.body, 'hex'),
    ].join('\n');

    var credentialString = [ date, region, service, 'aws4_request' ].join('/');

    var stringToSign = [
        'AWS4-HMAC-SHA256',
        datetime,
        credentialString,
        hash(canonicalString, 'hex')
    ] .join('\n');

    request.headers.Authorization = [
        'AWS4-HMAC-SHA256 Credential=' + process.env.AWS_ACCESS_KEY_ID + '/' + credentialString,
        'SignedHeaders=' + signedHeaders,
        'Signature=' + hmac(kSigning, stringToSign, 'hex')
    ].join(', ');

    return request;
}

function hmac(key, str, encoding) {
    return crypto.createHmac('sha256', key).update(str, 'utf8').digest(encoding);
}

function hash(str, encoding) {
    return crypto.createHash('sha256').update(str, 'utf8').digest(encoding);
}
