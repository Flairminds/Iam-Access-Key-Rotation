import json
import boto3
import os
from datetime import datetime, timedelta, timezone
 
iam = boto3.client('iam')
secretsmanager = boto3.client('secretsmanager')
ssm_client = boto3.client('ssm')

 
def lambda_handler(event, context):
    vsecret = os.getenv('secrets')
    secret_list = vsecret.split(';')
 
    for secret in secret_list:
        # Extracting the key details from IAM
        UserName = secret

        # Check key details directly in IAM
        key_response = iam.list_access_keys(UserName=UserName)

        # Check if user has any keys
        if not key_response['AccessKeyMetadata']:
            print("User " + UserName + " has no access keys.")
            create_response = iam.create_access_key(UserName=UserName)
            print("Created New Access Key")
            continue
 
        for key in key_response['AccessKeyMetadata']:
            # Get Creation Date
            accesskeydate = key['CreateDate'].replace(tzinfo=timezone.utc)
            # Check if key is older than 5 minutes (changed from 90 minutes)
            if datetime.utcnow().replace(tzinfo=timezone.utc) - accesskeydate >= timedelta(minutes=1):
                # Create a new key
                create_response = iam.create_access_key(UserName=UserName)
                print("A new set of keys has been created for user - " + UserName)
                # Updating values in parameter store

                NewSecret = '{"UserName":"' + create_response['AccessKey']['UserName'] + '", "AccessKeyId":"' + create_response['AccessKey']['AccessKeyId'] + '", "SecretAccessKey":"' + create_response['AccessKey']['SecretAccessKey'] + '"}'
                NewSecret_dict = json.loads(NewSecret)

                NewAccessKeyId = NewSecret_dict['AccessKeyId']
                SecretAccessKey = NewSecret_dict['SecretAccessKey']

                print("Updating Access for User" + UserName + "in parameter store" )

                ssm_client.put_parameter(Name=UserName + "_AccessKeyID",Value=NewAccessKeyId,Type='String',Overwrite=True)
                ssm_client.put_parameter(Name=UserName + "_secretkey",Value=SecretAccessKey,Type='String',Overwrite=True)

            else:
                print("Access key is less than 5 minutes old for the user - " + UserName)
 
    return "Process key creation & secret update has completed successfully."