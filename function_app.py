import azure.functions as func
# Libraries 
import os
from dotenv import load_dotenv
import time
import json

# Imports
from utils.logger import setup_logger
from src.email_template import EmailTemplateMaker
from src.requests import APICaller
from src.json_parser import JSONParser


app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="httppost", methods=["POST"])
def http_post(req: func.HttpRequest) -> func.HttpResponse:
    logger = setup_logger().getLogger(__name__)
    load_dotenv()
    
    username = os.getenv("USR")
    password = os.getenv("PASS")
    auth_token = os.getenv("AUTH")

    logger.info("Starting the main script...")
    
    try:
        # TODO uncomment this
        client_token = req.headers.get("auth")
        if (client_token != auth_token):
            return func.HttpResponse(
                body="You shall not be authenticated",
                status_code=403,
                mimetype="application/json"
            )
        
        logger.info("Fetching all the registers")
        api_obj = APICaller(username=username, password=password)
        api_fetched_data = api_obj.get_registers()
        logger.info("Fetched all the registers")
        print("Finished fetching registers")
        
        logger.info("Parsing all json data")
        parse_obj = JSONParser(json_obj=api_fetched_data, api_obj=api_obj)
        res_map = parse_obj.out_map
        logger.info("Parsed all json data")
        print("Finished parsing all the json data")
        
        logger.info("Making email templates and sending emails")
        email_template_obj = EmailTemplateMaker(res_map=res_map)
        _, res = email_template_obj.make_email()
        logger.info("Finishing making email templates and sending emails")
        print("Finished making emails and sending them")
        
        logger.info("Program finished")
        print("Program finished")
        
        return func.HttpResponse(
            body=json.dumps({"emails" : res}),
            status_code=200,
            mimetype="application/json"
        )
        
        
    except Exception as e:
        print(f"Error occurred: {e}")
        import sys; sys.exit(1)
        