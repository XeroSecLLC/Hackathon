import pprint

from tenabledata import get_assets

a = get_assets()

for asset in a:
    pprint.pprint(str(asset))
