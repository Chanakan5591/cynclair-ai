from datasource import QRadar

class QRadarSearch:
    def __init__(self, query: str):
        self.qradar = QRadar(query)

    def search(self):
        return self.qradar.get_info()
