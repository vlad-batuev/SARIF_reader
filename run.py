import json
import datetime
from database import Database

class SarifParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.sarif_data = self.read_sarif_file()

    def read_sarif_file(self):
        with open(self.file_path, 'r') as file:
            return json.load(file)

    def get_tool_info(self):
        runs = self.sarif_data.get('runs')
        if runs:
            for run in runs:
                tool = run.get('tool')
                if tool:
                    return tool.get('driver')
        return None

    def get_issues(self):
        runs = self.sarif_data.get('runs')
        if runs:
            for run in runs:
                return run.get('results')
        return None

    def get_issue_details(self, issue):
        return {
            'ruleId': issue.get('ruleId'),
            'message': issue.get('message'),
            'locations': issue.get('locations')
        }

    def save_vulnerabilities(self, db):
        issues = self.get_issues()
        if issues is not None:
            for issue in issues:
                issue_details = self.get_issue_details(issue)
                for location in issue_details['locations']:
                    physical_location = location.get('physicalLocation')
                    if physical_location:
                        artifact_location = physical_location.get('artifactLocation')
                        if artifact_location:
                            uri = artifact_location.get('uri')
                            if uri:
                                current_time = datetime.datetime.now()
                                tool = self.get_tool_info()
                                db.insert_data('vulnerabilities', (issue_details['ruleId'], issue_details['message']['text'], uri, current_time, tool.get('name')))


    def print_issues(self):
        issues = self.get_issues()
        if issues is not None:
            for issue in issues:
                issue_details = self.get_issue_details(issue)
                print(f"Rule ID: {issue_details['ruleId']}")
                print(f"Message: {issue_details['message']['text']}")
                print("Locations:")
                for location in issue_details['locations']:
                    physical_location = location.get('physicalLocation')
                    if physical_location:
                        artifact_location = physical_location.get('artifactLocation')
                        if artifact_location:
                            uri = artifact_location.get('uri')
                            if uri:
                                print(f"  - {uri} \n {40 * '='}")
                            else:
                                print("  URI not available")
                        else:
                            print("  Artifact location not available")
                    else:
                        print("  Physical location not available")
                print()
        else:
            print("No issues found.")


if __name__ == "__main__":
    db = Database('vulnerabilities.db')
    db.create_table('vulnerabilities', ['rule_id TEXT', 'message TEXT', 'uri TEXT', 'current_time TEXT', 'tool TEXT'])
    db.add_column('vulnerabilities', 'tool', 'TEXT')
    parser = SarifParser('horusec.sarif')
    parser.save_vulnerabilities(db)
    parser.print_issues()
    db.close_connection()