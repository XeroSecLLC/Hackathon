import os
import openai
import re

openai.api_key = "no"


def get_powershell_code(input_string):
    pattern = '```powershell(.*?)```'
    match = re.search(pattern, input_string, re.DOTALL)

    return match.group(1).strip() if match else ''


class PromptData:
    def __init__(self, vuln_name, plugin_id, computer_name, solution, os):
        self.vuln_name = vuln_name
        self.plugin_id = plugin_id
        self.computer_name = computer_name
        self.solution = solution
        self.os = os


def gen_soltuion(prompt_data: PromptData):

    completion = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "user",
             "content": f"""Using the following output from tenable.io design a script in PowerShell to fix the vulnerability presented.  I will provide the description, plugin ID, OS, computer name, and text from tenable that provides the solution.
Name: {prompt_data.vuln_name}
Plugin ID:{prompt_data.plugin_id}
Computer Name: {prompt_data.computer_name}
Solution: {prompt_data.solution}
OS: {prompt_data.os}
If a file such as an .msi or exe file needs to be downloaded put a placeholder such as (URL to MSI File) and download the MSI file using System.Net.WebClient.
First download the file to a temp directory
Don’t try and look for the program, just execute the solution
"""}
        ]
    )

    S = completion.choices[0].message["content"]
    X = get_powershell_code(S)
    return X
