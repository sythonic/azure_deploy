from collections import defaultdict
from datetime import datetime
import re
import json

from src.requests import APICaller
from utils.logger import setup_logger

logger = setup_logger().getLogger(__name__)

class JSONParser:
    """Parses the json object and returns a map of remediation owners to their respective findings
    """
    def __init__(self, json_obj: dict, api_obj: APICaller):
        self.json_obj = json_obj
        self.api_obj = api_obj
        self.out_map = defaultdict(list)
        self.parse_json()
        
    def parse_json(self):    
        for r in self.json_obj['records']:
            # if status is remediated or closed we skip over
            if r['record']['sections'][5]['fields'][2]['simpleValue'] == "Remediated": continue
            if r['record']['sections'][5]['fields'][2]['simpleValue'][0].split(" ")[0] == "Closed": continue
            
            # always annoying to deal with
            if r['record']['sections'][1]['fields'][0]['simpleValue'][0] == "Red Team Exercise": continue
            
            remediation_name = r['record']['sections'][1]['fields'][5]['simpleValue'][0]
            risk_level = r['record']['sections'][4]['fields'][3]['simpleValue'][0]
            remediation_status = r['record']['sections'][5]['fields'][2]['simpleValue'][0]
            
            # if asset name doesnt exist skip for now (only should affect pen testing rows)
            if (r['record']['sections'][2]['fields'][0].get('simpleValue') == None):
                continue
            
            asset_name = r['record']['sections'][2]['fields'][0]['simpleValue'][0]
            
            if (self.parse_time(r['record']['sections']) == None):
                continue
            
            remediation_owner = self.parse_rem_owner(r['record']['sections'])
            internet_facing = self.parse_internet_facing(asset_name)
     
            value = {
                "finding_name": remediation_name,
                "risk_level": risk_level,
                "owner": remediation_owner,
                "remediation_status": remediation_status,
                "asset_name": asset_name,
                "date_found": self.parse_time(r['record']['sections']),
                "email": self.parse_email(remediation_owner),
                "id": r['record']['id'],
                "internet_facing": internet_facing
            }
            
            self.out_map[remediation_owner].append(value) 
            
        return self.out_map

    def parse_internet_facing(self, asset_name : str) -> str:
        """Calls the protecht api to get the internet facing status of the asset

        Args:
            asset_name (str): _description_
        """
        internet_facing = "N/A"
        try:
            internet_facing = json.loads(self.api_obj.get_information_facing(asset_name))[
                "records"
            ][0]["record"]["sections"][1]["fields"][18]["simpleValue"][0]
        except Exception:
            logger.warning(f"[parse_internet_facing({asset_name})] Skipped {asset_name} due to name not being found")
             
        return internet_facing
        
    def parse_time(self, res_obj : dict) -> datetime:
        """Parses the time from the incosistent format and returns a datetime object

        Args:
            res_obj (dict): json object containing multiple times 
            
            Supported formats:
            - DD/MM/YYYY or DD/MM/YY (e.g., 01/01/2023 or 01/01/23)
            - DD-MMM-YY or DD-MMM-YYYY (e.g., 01-Jan-23 or 01-Jan-2023)
            - MMM-YY or MMM-YYYY (e.g., Jan-23 or Jan-2023)
            - Month YYYY (e.g., January 2023)
        
        Returns:
            tuple(datetime, str): tuple object of the parsed time and the field it was found in
        Raises:
            Exception: if the time string is not in a supported format
        """
        month_map = {
            "jan": 1, "january": 1,
            "feb": 2, "february": 2,
            "mar": 3, "march": 3,
            "apr": 4, "april": 4,
            "may": 5,
            "jun": 6, "june": 6,
            "jul": 7, "july": 7,
            "aug": 8, "august": 8,
            "sep": 9, "september": 9,
            "oct": 10, "october": 10,
            "nov": 11, "november": 11,
            "dec": 12, "december": 12
        }
        
        # date first found can be blank or (n/a || na)
        # need to use get as it will return None if it doesnt exist
        # way more parsing is going to have to be done
        # [DD/MM/YY, DD/MM/YYYY, DD-MON-YY, DD-MON, DAY MONTH]
        
        '''
        res_obj['records'][0]['record']['sections'][5]['fields'][3]['simpleValue'][0]       Remediation date
        res_obj['records'][0]['record']['sections'][3]['fields'][7]['simpleValue'][0]       Date first found
        res_obj['records'][0]['record']['sections'][0]['fields'][1]['simpleValue'][0]       Create Date
        '''
        time_str, field_found = "", ""
        if (res_obj[5]['fields'][3].get('simpleValue')):
            time_str, field_found = res_obj[5]['fields'][3]['simpleValue'][0], "Remediation date"
        elif (res_obj[3]['fields'][7].get('simpleValue')):
            time_str, field_found = res_obj[3]['fields'][7]['simpleValue'][0], "Date first found"
        else:
            # This else might be cooked i.e UB
            time_str, field_found = res_obj[0]['fields'][1]['simpleValue'][0], "Create Date"

        try:
            # DD/MM/YYYY or DD/MM/YY this should be default on going
            if match := re.match(r"^(\d{1,2})/(\d{1,2})/(\d{2,4})$", time_str):
                day = int(match.group(1))
                month = int(match.group(2))
                year = match.group(3)
                
                if len(year) == 2:
                    year = "20" + year
                    
                return datetime(int(year), month, day), field_found
            
            # DD-MMM-YY or DD-MMM-YYYY
            elif match := re.match(r"^(\d{1,2})-([A-Za-z]{3,})-(\d{2,4})$", time_str):
                day = int(match.group(1))
                month_str = match.group(2).lower()
                year = match.group(3)
                
                if len(year) == 2:
                    year = "20" + year
                    
                if month_str[:3] in month_map:
                    month = month_map[month_str[:3]]
                    return datetime(int(year), month, day), field_found
            
            # MMM-YY or MMM-YYYY
            elif match := re.match(r"^([A-Za-z]{3,})-(\d{2,4})$", time_str):
                month_str = match.group(1).lower()
                year = match.group(2)
                
                if len(year) == 2:
                    year = "20" + year
                    
                if month_str[:3] in month_map:
                    month = month_map[month_str[:3]]
                    # default to first day of the month
                    return datetime(int(year), month, 1), field_found
                
            # Find space seperated ones
            elif len(time_str.split(" ")) == 2:
            
                # Month YYYY
                if match := re.match(r"^([A-Za-z]+)\s+(\d{4})$", time_str):
                    month_str = match.group(1).lower()
                    year = match.group(2)
                    
                    if month_str[:3] in month_map:
                        month = month_map[month_str[:3]]
                        return datetime(int(year), month, 1), field_found
                        
                # Month YY
                elif match := re.match(r"^([A-Za-z]+)\s+(\d{2})$", time_str):
                    month_str = match.group(1).lower()
                    year = "20" + match.group(2)
                    
                    if month_str[:3] in month_map:
                        month = month_map[month_str[:3]]
                        return datetime(int(year), month, 1), field_found
                    
                # YYYY-MM-DD (Random time)
                elif match := re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$", time_str):
                    time_arr = match.group(0).split(" ")[0].split("-")
                    return datetime(int(time_arr[0]), int(time_arr[1]), int(time_arr[2])), field_found
                    
            return None
            
        except (Exception):
            return None
    
    def parse_email(self, name : str) -> str:
        """Gets the email of the remediation owner from the api

        Args:
            name (str): name of the remediation owner

        Returns:
            str: email of the remediation owner
        """
        # This assumes every name is unique
        return json.loads(self.api_obj.get_emails(name[0]))["records"][0]["email"]
    
    
    def parse_rem_owner(self, res_obj):
        """Goes through a hierarchy of fields to find the remediation owner
        and returns it

        Args:
            res_obj (dict): object containing the fields to parse

        Returns:
            tuple(str, str): tuple of the remediation owner and the field it was found in
        """
        # res obj is res['sections']
        # 7 is rem owner
        # 6 is bus owner
        # bus owner = res_obj[5]['fields'][6]['parameters']['displayValues'][0]
        # rem owner = res_obj[5]['fields'][7]['parameters']['displayValues'][0]
        # created by = res_obj[0]['fields'][2]['parameters']['displayValues'][0]
        
        
        # MAYBE GO REM OWNER -> BUS OWNER -> CREATED BY
        # might not have to check the final if to see if it exists
        try:
            # Try remediation owner
            if 'parameters' in res_obj[5]['fields'][7] and 'displayValues' in res_obj[5]['fields'][7]['parameters']:
                rem_owner = res_obj[5]['fields'][7]['parameters']['displayValues'][0]
                if rem_owner:
                    return rem_owner, "Remediation Owner"

            if 'parameters' in res_obj[5]['fields'][6] and 'displayValues' in res_obj[5]['fields'][6]['parameters']:
                bus_owner = res_obj[5]['fields'][6]['parameters']['displayValues'][0]
                if bus_owner:
                    return bus_owner, "Business Owner"

            if 'parameters' in res_obj[0]['fields'][2] and 'displayValues' in res_obj[0]['fields'][2]['parameters']:
                created_by = res_obj[0]['fields'][2]['parameters']['displayValues'][0]
                if created_by:
                    return created_by, "Created By"

        except (Exception) as e:
            return None

        # Final fallback
        return None
