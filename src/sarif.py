import json
import datetime

from pathlib import Path

from database.database import Database
from logger.loger import logger


class SarifParser:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.sarif_data = self.read_sarif_file()

    def __call__(self):
        db = Database(f'{self.file_path.name}.db')
        #TODO Добавить критичность уязвимости, новая ли она, статус
        db.create_table('vulnerabilities', [
            'rule_id TEXT', 'message TEXT', 'uri TEXT', 'current_time TEXT',
            'tool TEXT'
        ])
        db.add_column('vulnerabilities', 'tool', 'TEXT')
        self.save_vulnerabilities(db)
        self.print_issues()
        db.close_connection()

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
            'locations': issue.get('locations'),
        }

    def save_vulnerabilities(self, db):
        issues = self.get_issues()
        if issues is not None:
            for issue in issues:
                issue_details = self.get_issue_details(issue)
                for location in issue_details['locations']:
                    physical_location = location.get('physicalLocation')
                    if physical_location:
                        artifact_location = physical_location.get(
                            'artifactLocation')
                        if artifact_location:
                            uri = artifact_location.get('uri')
                            if uri:
                                current_time = datetime.datetime.now()
                                tool = self.get_tool_info()
                                db.insert_data(
                                    'vulnerabilities',
                                    (issue_details['ruleId'],
                                     issue_details['message']['text'], uri,
                                     current_time, tool.get('name')))

    def print_issues(self):
        issues = self.get_issues()
        if issues is not None:
            for issue in issues:
                issue_details = self.get_issue_details(issue)
                logger.info(
                    f"Rule ID: {issue_details['ruleId']}\n"
                    f"Message: {issue_details['message']['text']}\n"
                )
                for location in issue_details['locations']:
                    logger.info(
                        f"Snippet: {location.get('physicalLocation').get('region').get('snippet').get('text')}\n"
                        f"startLine: {location.get('physicalLocation').get('region').get('startLine')}\n"
                        f"endLine: {location.get('physicalLocation').get('region').get('endLine')}\n"
                    )
                    physical_location = location.get('physicalLocation')
                    if physical_location:
                        artifact_location = physical_location.get(
                            'artifactLocation')
                        if artifact_location:
                            uri = artifact_location.get('uri')
                            if uri:
                                logger.info(f"  - {uri} \n {40 * '='}\n\n")
                            else:
                                logger.info("  URI not available")
                        else:
                            logger.info("  Artifact location not available")
                    else:
                        logger.info("  Physical location not available")
        else:
            logger.info("No issues found.")
