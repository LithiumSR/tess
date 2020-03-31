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

    def get(self, *argv):
        self._check_connnection()
        collection = self.connection['cvss_details']
        print(argv)
        return collection.find(*argv)

    def get_collection(self):
        self._check_connnection()
        return self.connection['cvss_details']

    def _check_connnection(self):
        if not self.is_connected():
            raise Exception('Driver for MongoDB is not connected')

    def close_connection(self):
        self.client.close()
        self.client = None
        self.connection = None

    def is_connected(self):
        return self.client is not None and self.connection is not None
