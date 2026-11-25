def connect(self) -> dict:
    """
    Set up the connection required by the handler.
    Returns:
        HandlerStatusResponse
    """

    headers_renamed = {
        'Content-Type': 'application/json',
    }

    data = '{' + f'"userName": "{self.connection_data["username"]}","password": "{self.connection_data["password"]}"' + '}'

    response = requests.post(self.base_url + '/apiv2/login', headers=headers_renamed, data=data)

    return {
        'Authorization': '_dremio' + response.json()['token'],
        'Content-Type': 'application/json',
    }