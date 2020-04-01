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
        self.connection = self.client['cve-search-database']

    def write_info_cve(self, info, year, meta_hash):
        self._check_connnection()
        collection = self.connection['info-cve']
        info['_id'] = year
        info['meta_hash'] = meta_hash
        collection.replace_one({"_id": year}, info, True)

    def write_info_capec(self, info):
        self._check_connnection()
        collection = self.connection['info-capec']
        collection.replace_one({"_id": 0}, info, True)

    def get_info_capec(self):
        self._check_connnection()
        collection = self.connection['info-capec']
        return collection.find_one({"_id": 0})

    def get_info_cve(self, year):
        self._check_connnection()
        collection = self.connection['info-cve']
        return collection.find_one({"_id": year})


    def write_details_cve(self, entry):
        self._check_connnection()
        collection = self.connection['cve_details']
        el_id = entry['cve']['CVE_data_meta']['ID']
        entry['_id'] = el_id
        collection.replace_one({"_id": el_id}, entry, True)

    def write_entry_capec(self, entry):
        self._check_connnection()
        collection = self.connection['capec_details']
        entry['_id'] = entry['id']
        collection.replace_one({"_id": entry['_id']}, entry, True)

    def get_cve(self, *argv):
        self._check_connnection()
        collection = self.connection['cve_details']
        return collection.find(*argv)

    def get_capec(self, *argv):
        self._check_connnection()
        collection = self.connection['capec_details']
        return collection.find(*argv)

    def get_collection(self, name):
        self._check_connnection()
        return self.connection[name]

    def _check_connnection(self):
        if not self.is_connected():
            raise Exception('Driver for MongoDB is not connected')

    def close_connection(self):
        self.client.close()
        self.client = None
        self.connection = None

    def is_connected(self):
        return self.client is not None and self.connection is not None
