from pymongo import MongoClient


class MongoDriver:

    def __init__(self, server='localhost', port=27017):
        self.client = None
        self.connection = None
        self.server = server
        self.port = port
        if server is None:
            self.server = 'localhost'
        if port is None:
            self.port = 27017

    def connect(self):
        self.client = MongoClient(self.server, self.port)
        print(self.client)
        self.connection = self.client['cvss-database']

    def write_info(self, info, year):
        self._check_connnection()
        collection = self.connection['info']
        info['_id'] = year
        collection.replace_one({"_id": year}, info, True)

    def write_details(self, details):
        self._check_connnection()
        collection = self.connection['cvss_details']
        for el in details:
            copy = dict(el)
            el_id = el['cve']['CVE_data_meta']['ID']
            copy['_id'] = el_id
            collection.replace_one({"_id": el_id}, copy, True)

    def get(self, filter):
        self._check_connnection()
        collection = self.connection['cvss_details']
        return collection.find(filter)

    def _check_connnection(self):
        if self.connection is None:
            raise Exception('Driver for MongoDB is not connected')
