import requests
from requests.auth import HTTPBasicAuth
import json
from utils.logger import setup_logger

logger = setup_logger().getLogger(__name__)


class APICaller:
    """Sends requests to the protecht API
    """
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.auth = HTTPBasicAuth(username, password)

    def fetchRegisters(self, offset: int) -> str:
        """Uses protecht API to fetch registers

        Args:
            offset (int): offset used for pagination

        Returns:
            str: json string of the registers

        Raises:
            Exception: if the request fails
        """
        # https://ermgov.protecht.com.au/unswcybergov/rest/docs/?urls.primaryName=Default%20-%20REST%20v2.0#/Register%20Entries%20v2/getRegisterEntriesSearchPOST
        base_url = "https://ermgov.protecht.com.au/unswcybergov/rest"
        reg_id = 7246
        params = {
            "keys": "col_135040",  # this is the column name for the status column
            "values": "Open",
            "limit": 50,
            "offset": offset,
        }

        res = requests.post(
            f"{base_url}/v2/service/entries/{reg_id}/search",
            auth=self.auth,
            params=params,
        )

        if res.status_code == 200:
            return res.text
        else:
            logger.error(
                f"[fetchRegisters({offset})] Error: {res.status_code}, {res.text}"
            )
            raise Exception(
                f"[fetchRegisters({offset})] Error: {res.status_code}, {res.text}"
            )

    def get_emails(self, name: str) -> str:
        """Uses protecht API to fetch emails from the user name is findings register

        Args:
            name (str): name of the user

        Returns:
            str: Email of the user
        Raises:
            Exception: if the request fails
        """
        base_url = "https://ermgov.protecht.com.au/unswcybergov/rest"
        filter_context_rest = {
            "expressions": [
                {"expression": "=", "property": "name", "type": "STRING", "value": name}
            ]
        }

        res = requests.post(
            f"{base_url}/v2/service/users/search",
            auth=self.auth,
            json=filter_context_rest,
        )

        if res.status_code == 200:
            return res.text
        else:
            logger.error(f"[get_emails({name})] Error: {res.status_code}, {res.text}")
            raise Exception(f"[get_emails({name})] Error: {res.status_code}, {res.text}")

    def get_information_facing(self, resource) -> str:
        """Uses protecht API to fetch information facing info from the asset name is findings register
        Args:
            resource (str): name of the resource

        Returns:
            str: if it is internet facing or not
        Raises:
            Exception: if the request fails
        """
        base_url = "https://ermgov.protecht.com.au/unswcybergov/rest"
        reg_id = 935
        params = {
            "keys": "col_113150",
            "values": resource,
        }

        res = requests.post(
            f"{base_url}/v2/service/entries/{reg_id}/search",
            auth=self.auth,
            params=params,
        )

        if res.status_code == 200:
            return res.text
        else:
            logger.error(
                f"[get_information_facing({resource})] Error: {res.status_code}, {res.text}"
            )
            raise Exception(
                f"[get_information_facing({resource})] Error: {res.status_code}, {res.text}"
            )

    def get_registers(self) -> dict:
        """Uses pagination to fetch all registers from the API

        Returns:
            dict: json object of the registers

        Raises:
            Exception: if the record count is not equal to total count
        """

        json_obj = json.loads(self.fetchRegisters(0))

        # effective pagination could be improved with multithreading
        # see if this works
        if json_obj["totalCount"] > json_obj["maxPage"]:
            for i in range(50, json_obj["totalCount"], json_obj["maxPage"]):
                other_json = json.loads(self.fetchRegisters(i))
                for record in other_json["records"]:
                    json_obj["records"].append(record)

        if json_obj["totalCount"] != len(json_obj["records"]):
            logger.error(
                f"[get_registers] json_obj record count is not equal to total_count ({json_obj['totalCount']} != {len(json_obj['records'])})"
            )
            raise Exception(
                f"[get_registers] json_obj record count is not equal to total_count ({json_obj['totalCount']} != {len(json_obj['records'])})"
            )

        logger.info(f"[get_registers] Succesffully fetched {len(json_obj['records'])} records")
        return json_obj


