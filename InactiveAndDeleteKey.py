import json
import boto3
import os
from datetime import datetime, timedelta

iam = boto3.client('iam')
secretsmanager = boto3.client('secretsmanager')

def lambda_handler(event, context):
    
    vsecret = os.getenv('secrets')
    secret_list = vsecret.split(';')

    for secret in secret_list:
        UserName = secret

        print("For user - " + UserName + ", inactive Access & Secret keys will be deleted.")
        
        # Extracting the key details from IAM
        key_response = iam.list_access_keys(UserName=UserName)
        
        # Inactive Key Deletion
        for key in key_response['AccessKeyMetadata']:
            # Calculate the time difference between now and key creation
            creation_time = key['CreateDate']
            current_time = datetime.now(creation_time.tzinfo)
            time_difference = current_time - creation_time
            
            # If key was created more than 5 minutes ago, inactivate and after >6 it delete it
            if time_difference.total_seconds() > 360:  # 6 minutes in seconds
                if key['Status'] == 'Active':
                    iam.update_access_key(UserName=key['UserName'], AccessKeyId=key['AccessKeyId'], Status='Inactive')
                    print("An active key - " + key['AccessKeyId'] + ", of " + key['UserName'] + " user has been inactivated.")
                    
            if time_difference.total_seconds() > 420:   # 7 min in seconds
                iam.delete_access_key(AccessKeyId=key['AccessKeyId'], UserName=key['UserName'])
                print("An inactive key - " + key['AccessKeyId'] + ", of " + key['UserName'] + " user has been deleted.")
    
    return "Process of inactive key deletion completed successfully."