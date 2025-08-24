import re

pat = re.compile(r"(Failed password)", re.I)

with open("/workspaces/blue-team/suspicsuspicious_log.txt", "r") as infile:
    for line in infile:
        if pat.search(line):  # check if line contains "Failed password"
            with open("failed_password_log.txt", "a") as failedfile:
                failedfile.write(line)
