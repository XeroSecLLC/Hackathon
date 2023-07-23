from tenable.io import TenableIO


class Vulnerability:
    def __init__(self, name, id, severity, description, solution, cve, synopsis, family):
        self.name = name
        self.id = id
        self.severity = severity
        self.description = description
        self.solution = solution
        self.cve = cve
        self.synopsis = synopsis
        self.family = family

    def __str__(self):
        return "Name: " + str(self.name) + "\n\tID: " + str(self.id) + "\n\tSeverity: " + str(self.severity) + "\n\tDescription: " + str(self.description) + "\n\tSolution: " + str(self.solution) + "\n\tCVE: " + str(self.cve) + "\n\tSynopsis: " + str(self.synopsis) + "\n\tFamily: " + str(self.family) + "\n"

    # Make class sortable based on severity
    def __lt__(self, other):
        return float(self.severity) < float(other.severity)


class Asset:
    def __init__(self, name, id, vulnerabilities, os_version):
        self.name = name
        self.id = id
        self.vulnerabilities = vulnerabilities
        self.os_version = os_version

    def __str__(self):
        vul_str = ""

        for vul in self.vulnerabilities:
            vul_str += str(vul)

        return "Name: " + str(self.name) + "\n\tID: " + str(self.id) + "\n\tOS Version: " + str(self.os_version) + "\n" + str(vul_str) + "\n\n"


def get_assets():
    tio = TenableIO(
        'no', 'no')
    print('getting assets')
    assets = []

    for asset in tio.assets.list():
        # pprint.pprint(asset)
        # print("************iajsdoifj******8")
        vulns = tio.workbenches.asset_vulns(asset['id'])

        vulns_add = []

        for vuln in vulns:
            # pprint.pprint(vuln)
            # print('blah************************')
            plugin = tio.plugins.plugin_details(vuln['plugin_id'])
            # pprint.pprint(plugin)

            description = ""
            solution = ""
            cve = None
            synopsis = ""
            family = ""

            for attribute in plugin['attributes']:
                if attribute['attribute_name'] == 'description':
                    description = attribute['attribute_value']
                elif attribute['attribute_name'] == 'solution':
                    solution = attribute['attribute_value']
                elif attribute['attribute_name'] == 'cve':
                    cve = attribute['attribute_value']
                elif attribute['attribute_name'] == 'synopsis':
                    synopsis = attribute['attribute_value']
                elif attribute['attribute_name'] == 'family':
                    family = attribute['attribute_value']

            vulns_add.append(Vulnerability(vuln['plugin_name'],
                                           vuln['plugin_id'],
                                           vuln['severity'],
                                           description,
                                           solution,
                                           cve,
                                           synopsis,
                                           family))

        assets.append(Asset(asset['hostname'][0],
                            asset['id'], vulns_add, asset['operating_system'][0]))

    return assets
