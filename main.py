from flask import Flask, render_template
from gpt import PromptData, gen_soltuion
from tenabledata import get_assets

app = Flask(__name__)


@app.route('/')
def index():
    global assets

    asset_table_data = []

    for asset in assets:
        a = dict()
        a['name'] = asset.name
        a['id'] = asset.id
        a['os'] = asset.os_version
        a['num_vulns'] = len(asset.vulnerabilities)

        asset_table_data.append(a)

    return render_template('index.html', assets=asset_table_data)


def select_asset_from_id(id: str):
    asset = None

    for a in assets:
        if a.id == id:
            asset = a
            break

    if asset is None:
        raise KeyError

    return asset


def select_vuln_from_id(id, vulns):
    vuln = None

    for v in vulns:
        if int(v.id) == int(id):
            vuln = v
            break

    if vuln is None:
        raise KeyError

    return vuln


@ app.route('/asset/<id>')
def show_asset(id: str):
    asset = None
    try:
        asset = select_asset_from_id(id)
    except KeyError:
        return "404 Not Found", 404

    a = dict()
    a['name'] = asset.name
    a['id'] = asset.id
    a['os'] = asset.os_version
    a['num_vulns'] = len(asset.vulnerabilities)

    asset.vulnerabilities.sort(reverse=True)

    return render_template('asset.html', asset=a, vulns=asset.vulnerabilities)


@ app.route('/asset/<id>/<vuln_id>')
def show_vuln(id: str, vuln_id: str):
    try:
        asset = select_asset_from_id(id)
        vuln = select_vuln_from_id(vuln_id, asset.vulnerabilities)
    except KeyError:
        return "404 Not Found", 404

    return render_template('vulnerability.html', asset=asset, vuln=vuln)


@ app.route('/asset/<id>/<vuln_id>/fix')
def show_vuln_fix(id: str, vuln_id: str):
    try:
        asset = select_asset_from_id(id)
        vuln = select_vuln_from_id(vuln_id, asset.vulnerabilities)
    except KeyError:
        return "404 Not Found", 404

    prompt_data = PromptData(
        vuln.name, vuln.id, asset.name, vuln.solution, asset.os_version)

    return render_template('vulnerabilityfix.html', vuln=vuln, fix=gen_soltuion(prompt_data))


if __name__ == '__main__':
    global assets

    assets = get_assets()
    print('running')
    app.run()
