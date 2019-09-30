from __future__ import print_function

import decimal
import hashlib
import hmac
import json
import os
import boto3
import time
import jose.jwt
import requests
import base64
import datetime
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from jose.exceptions import JWTError


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)


def generatePolicy(principalId, sid, effect, getAccess, checkResource, apiId, awsAccount, region):
    global policyDocument

    config = {
        "apigateway_setup": {
            "ref": "arn:aws:execute-api"
        }

    }

    ref = config['apigateway_setup']['ref']

    methodArn = ref + ":" + region + ":" + awsAccount + ":" + apiId + "/*/"

    if checkResource in getAccess:
        # serviceAccessList = [methodArn + x for x in serviceList]
        serviceAccessList = [methodArn + checkResource]
        policyDocument = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': sid,
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': serviceAccessList

                }
            ]
        }

    else:
        return generateDenyPolicy("", "DenyAll", 'Deny', "*")

    return policyDocument


def generateDenyPolicy(principalId, sid, effect, getAccess):
    return {

        'Version': '2012-10-17',
        'Statement': [
            {
                'Action': 'execute-api:Invoke',
                'Effect': "Deny",
                'Resource': "*"

            }
        ]
    }


def lambda_handler(event, context):
    try:
        print("Incoming Event:", event)
        serviceArn = event['methodArn']
        getId = serviceArn.split(":")
        getgatewayId = getId[5]
        apiId = getgatewayId.split("/")
        gatewayId = apiId[0]
        getRegion = getId[3]
        accountId = getId[4]
        path = event['path']
        httpMethod = event['httpMethod']
        pathVar = httpMethod + path
        getAuth = event['headers'].get('Authorization')
        """ Implement getting the User from your desired Authentication Process """
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    
    
        roleTable = dynamodb.Table(os.environ['ROLE_TABLE'])
        """ Get the arnList from the Role Table Map """
        # Example: arnList = ["GET/Api1","PUT/Api2"]
        # principalId = "userId"
        # sid = "Session ID"
        return {
            'principalId': principalId,
            'policyDocument': generatePolicy(principalId, sid, 'Allow', arnList, pathVar,
                                             gatewayId,
                                             accountId,
                                             getRegion),
            'context': {
                "_comment": "Add any Other Parameters that are needed"
            }
        
        }
    except JWTError:
    
    print("Bearer Token is Invalid")
    return {
        "principalId": "",
        "policyDocument": generateDenyPolicy("", "DenyAll", 'Deny', "*")
    
    }
