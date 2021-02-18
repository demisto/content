from typing import Tuple

import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import dateparser
import requests
import trustar
from trustar.models.indicator import Indicator
from trustar.models.report import Report

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

handle_proxy()


class Utils(object):
    """
    Class with some utility methods.
    """
    @staticmethod
    def normalize_time(timestamp):
        ''' Converts unix epoch time to GMT '''
        if isinstance(timestamp, str):
            return timestamp
        return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp / 1000.0))

    @staticmethod
    def date_to_unix(timestamp):
        d = dateparser.parse(timestamp)
        return int(d.strftime("%s")) * 1000


class ContextManager(object):
    """
    Manages where to put the data depending if the data to output is an indicator or not.

    If data is an indicator, the data is returned on 3 contexts:
    - DBotScore context: Contains the value of the IOC, the vendor (TruSTAR) and a score of 0.
    - Standard context: Groups all IOCs by types and returns the value of each one.
    - TruSTAR context: Contains all the information fetched from TruSTAR corresponding to each indicator.
    Data is also returned on the TruSTAR context for phishing submissions and reports.
    """

    INDICATOR_TYPES = {
        'URL': Common.URL,
        'IP': Common.IP,
        'DOMAIN': Common.Domain,
        'CVE': Common.CVE
    }

    DBOTSCORE_TYPES = {
        'URL': DBotScoreType.URL,
        'IP': DBotScoreType.IP,
        'DOMAIN': DBotScoreType.DOMAIN,
        'CVE': DBotScoreType.CVE,
        'SOFTWARE': DBotScoreType.FILE,
        'SHA256': DBotScoreType.FILE,
        'SHA1': DBotScoreType.FILE,
        'MD5': DBotScoreType.FILE,
    }

    FILE_TYPES = ['SOFTWARE', 'SHA256', 'SHA1', 'MD5']

    def _get_dbot_score(self, ts_indicator):
        """ Returns a DBotScore object with score as None """
        indicator_type = ts_indicator.get('indicatorType')
        dbot_score = Common.DBotScore(
            indicator=ts_indicator.get('value'),
            indicator_type=self.DBOTSCORE_TYPES.get(indicator_type),
            integration_name='TruSTAR',
            score=Common.DBotScore.NONE
        )
        return dbot_score

    def _get_xsoar_file_indicator(self, ts_indicator, dbot_score):
        """
        Returns a Common.File object. Handles logic to create the object with
        the corresponding type (SHA1, SHA256, MD5 or Name if software).
        """

        key = ts_indicator.get('indicatorType')
        key = "name" if key == "SOFTWARE" else key
        value = ts_indicator.get('value')
        args = {
            key.lower(): value,
            'dbot_score': dbot_score
        }
        xsoar_file_indicator = Common.File(**{k: v for k, v in args.items() if k})
        return xsoar_file_indicator

    def _get_xsoar_indicator_and_readable_output(self, ts_indicator) -> Tuple[Common.Indicator, str]:
        """
        Returns a XSoar Indicator with DBotScore embedded and their human readable. Indicators can be:
        - Common.File
        - Common.IP
        - Common.URL
        - Common.CVE
        """

        indicator_type = ts_indicator.get('indicatorType')
        if indicator_type == "CVE":
            return (Common.CVE(ts_indicator.get('value'), None, None, None, None),
                    f'Fetched CVE {ts_indicator.get("value")} details')

        dbot_score = self._get_dbot_score(ts_indicator)
        if indicator_type in self.FILE_TYPES:
            return (self._get_xsoar_file_indicator(ts_indicator, dbot_score),
                    f'Fetched File {ts_indicator.get("value")} details')

        XSOARIndicator = self.INDICATOR_TYPES.get(indicator_type)
        xsoar_indicator = XSOARIndicator(
            ts_indicator.get('value'),
            dbot_score=dbot_score
        ) if XSOARIndicator is not None else None
        return xsoar_indicator, f'Fetched {indicator_type} {ts_indicator.get("value")} details'

    def _remove_priority_level(self, indicator_dict):
        """  Removes priority level from indicator. It is a deprecated field """
        if indicator_dict.get('priorityLevel'):
            indicator_dict.pop('priorityLevel')

        return indicator_dict

    def get_context(self, indicators, context='Indicator'):
        """
        Handles logic to return an entry context with xsoar and non xsoar indicators
        on their corresponding contexts.
        """
        context_results: List[dict] = []
        indicators = [self.convert_indicator_timestamps(d) for d in indicators]
        indicators = [self._remove_priority_level(d) for d in indicators]
        xsoar_indicators = [
            self._get_xsoar_indicator_and_readable_output(d)
            for d in indicators
            if d.get('indicatorType') not in {'EMAIL_ADDRESS', 'REGISTRY_KEY', 'MALWARE', 'CIDR_BLOCK'}
        ]
        for xsoar_ioc, hr in xsoar_indicators:
            context_results.append(CommandResults(
                indicator=xsoar_ioc,
                readable_output=hr
            ).to_context())

        standard_context = self.get_non_xsoar_standard_context(indicators)
        results = CommandResults(
            outputs_prefix=f'TruSTAR.{context}',
            outputs_key_field='value',
            outputs=indicators,
        )
        context = results.to_context()
        context['EntryContext'].update(standard_context)

        # insert the TruStar result as the first item in results
        context_results.insert(0, context)
        return context_results

    def convert_indicator_timestamps(self, indicator):
        """ Converts indicator timestamp fields. """
        d = {
            t: Utils.normalize_time(indicator.get(t))
            for t in ['firstSeen', 'lastSeen']
            if t in indicator.keys()
        }
        indicator.update(d)
        return indicator

    def get_indicators_context(self, indicators, context='Indicators'):
        ts_indicator_dicts = [
            i.to_dict(remove_nones=True)
            for i in indicators
        ]

        return self.get_context(ts_indicator_dicts, context)

    def get_indicator_summaries_context(self, indicators, context='Indicators'):
        ts_indicator_dicts = [
            i.to_dict(remove_nones=True)
            for i in indicators
        ]

        for d in ts_indicator_dicts:
            d['indicatorType'] = d.pop('type')  # Adding IndicatorType field

        return self.get_context(ts_indicator_dicts, context)

    def get_non_xsoar_standard_context(self, indicator_dicts):
        """
        Returns a standard context for those indicator types that can not be automated
        with one of the 'Common' classes. Depending on the type of indicator,
        the data is put on the corresponding context.
        """
        emails = [
            {'Address': i.get('value')}
            for i in indicator_dicts
            if i.get('indicatorType') == "EMAIL_ADDRESS"
        ]

        registries = [
            {'Path': i.get('value')}
            for i in indicator_dicts
            if i.get('indicatorType') == "REGISTRY_KEY"
        ]
        standard_ec = {}
        if emails:
            standard_ec['Account.Email(val.Address && val.Address === obj.Address)'] = emails
        if registries:
            standard_ec['RegistryKey(val.Path && val.Path === obj.Path)'] = registries

        return standard_ec

    def translate_triage_submission(self, submissions):
        """ Returns Entry Contex for Phishing Submissions """
        submission_dicts = [s.to_dict(remove_nones=True) for s in submissions]
        ec = {'TruSTAR.PhishingSubmission(val.submissionId == obj.submissionId)': submission_dicts}
        return submission_dicts, ec

    def get_enclaves_ec(self, enclaves):

        context = [enclave.to_dict(remove_nones=True) for enclave in enclaves]
        ec = {
            'TruSTAR.Enclave(val.id && val.id === obj.id)': context
        }
        return context, ec

    def _get_report_context_fields(self, report):
        context_fields = ["id", "title", "reportBody"]
        fields = {k: v for k, v in report.items() if k in context_fields}
        return fields

    def get_reports_ec(self, reports):
        """ Returns entry context for Reports """
        context = [self._get_report_context_fields(report) for report in reports]
        ec = {
            'TruSTAR.Report(val.id && val.id === obj.id)': context
        }
        return ec

# ## CLIENT ###


class TrustarClient:
    """
    Class wrapper of TruSTAR SDK.

    Interpretates a command and retrieves the correspondding data
    from TruSTAR to be shown on the war room and put on the corresponding
    context.
    """

    LIST_ARGS = [
        "indicators",
        "indicator_types",
        "values",
        "enclave_ids",
        "priority_event_score",
        "normalized_indicator_score",
        "status",
        "tags",
        "exclueded_tags"
    ]

    def __init__(self, config, station=''):
        self.client = trustar.TruStar(config=config)
        self.command_dict = self._build_command_dict()
        self.context_manager = ContextManager()
        self.station = station

    def _build_command_dict(self):
        command_dict = {
            'test-module': self.test_module,
            'trustar-get-reports': self.get_reports,
            'trustar-get-enclaves': self.get_enclaves,
            'trustar-related-indicators': self.get_related_indicators,
            'trustar-indicators-metadata': self.get_indicators_metadata,
            'trustar-indicator-summaries': self.get_indicator_summaries,
            'trustar-get-whitelisted-indicators': self.get_whitelist,
            'trustar-move-report': self.move_report,
            'trustar-trending-indicators': self.get_trending_indicators,
            'trustar-get-indicators-for-report': self.get_indicators_for_report,
            'trustar-search-indicators': self.search_indicators,
            'trustar-submit-report': self.submit_report,
            'trustar-delete-report': self.delete_report,
            'trustar-correlated-reports': self.get_correlated_reports,
            'trustar-add-to-whitelist': self.add_to_whitelist,
            'trustar-remove-from-whitelist': self.remove_from_whitelist,
            'trustar-report-details': self.get_report_details,
            'trustar-update-report': self.update_report,
            'trustar-search-reports': self.search_reports,
            'trustar-get-phishing-indicators': self.get_all_phishing_indicators,
            'trustar-get-phishing-submissions': self.get_phishing_submissions,
            'trustar-set-triage-status': self.set_triage_status,
            'trustar-copy-report': self.copy_report
        }
        return command_dict

    def get_entry(self, title='', contents=None, ec=None):
        """
        Returns Context dictionary
        """
        entry = {
            'Type': EntryType.NOTE,
            'Contents': contents,
            'ContentsFormat': EntryFormat.JSON,
            'ReadableContentsFormat': EntryFormat.MARKDOWN,
            'HumanReadable': tableToMarkdown(title, contents),
        }
        if ec:
            entry['EntryContext'] = ec

        return entry

    def get_report_timestamps(self, report):
        """ Given a report dictionary, it returns the timestamp fields
        on a dictionary.
        """
        d = {
            t: Utils.normalize_time(report[t])
            for t in ['updated', 'created', 'timeBegan']
            if report.get(t)
        }
        return d

    def get_report_deep_link(self, report_id):
        """ Returns report link on TruSTAR self.station. """
        return f'{self.station}/constellation/reports/{report_id}'

    def test_module(self):
        """Tests connectivity with TruSTAR"""
        try:
            self.client.ping()
            return "ok"
        except requests.exceptions.HTTPError:
            return ("Invalid Credentials. Please check your API Key and Secret"
                    "are correct on TruSTAR Station. Settings > API")

    def search_indicators(self,
                          search_term=None,
                          enclave_ids=None,
                          from_time=None,
                          to_time=None,
                          indicator_types=None,
                          tags=None,
                          excluded_tags=None,
                          limit=None):
        """
        Searches for all indicators that contain the given search term.

        :param search_term: Term to be searched.
        :param enclave_ids: list of enclaves to restrict the search to.
        "param limit: Max number of entries to be returned.

        :return: Entry context with found indicators.
        """
        """
        Searches for all indicators that contain the given search term.

        :param search_term: Term to be searched.
        :param enclave_ids: list of enclaves to restrict the search to.
        "param limit: Max number of entries to be returned.

        :return: Entry context with found indicators.
        """
        from_time = Utils.date_to_unix(from_time) if from_time else from_time
        to_time = Utils.date_to_unix(to_time) if to_time else to_time
        try:
            response = self.client.search_indicators_page(
                search_term=search_term,
                enclave_ids=enclave_ids,
                from_time=from_time,
                to_time=to_time,
                tags=tags,
                indicator_types=indicator_types,
                excluded_tags=excluded_tags,
                page_number=0,
                page_size=limit,
            )

            if not response:
                return 'No indicators were found.'

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 400:
                return 'No indicators were found.'

            raise(err)

        results = self.context_manager.get_indicators_context(response)
        return results

    def get_reports(self,
                    from_time=None,
                    to_time=None,
                    enclave_ids=None,
                    distribution_type=None,
                    tags=None,
                    excluded_tags=None):
        """
        Returns incident reports matching the specified filters.

        :param from_time: Start of polling window.
        :param to_time: End of polling window.
        :param enclave_ids: List of user enclaves to restrict the query.
        :param distribution_type: Whether to search for reports in the community, or only
        in enclaves.
        :param tags: a list of names of tags to filter by.
        :param excluded_tags: reports containing ANY of these tags will be excluded from the
        results.

        :return: Entry context with found reports.
        """
        is_enclave = (distribution_type == 'ENCLAVE')
        from_time = Utils.date_to_unix(from_time) if from_time else from_time
        to_time = Utils.date_to_unix(to_time) if to_time else to_time
        response = self.client.get_reports_page(
            is_enclave,
            enclave_ids,
            tags,
            excluded_tags,
            from_time,
            to_time
        )

        if not response:
            return 'No reports were found.'

        reports = []
        for report in response.items:
            current_report = report.to_dict(remove_nones=True)
            current_report['reportDeepLink'] = self.get_report_deep_link(current_report.get("id"))
            current_report.update(self.get_report_timestamps(current_report))
            reports.append(current_report)

        ec = self.context_manager.get_reports_ec(reports)
        title = 'TruSTAR reports'
        entry = self.get_entry(title, reports, ec)
        return entry

    def submit_report(self,
                      title=None,
                      report_body=None,
                      enclave_ids=None,
                      external_url=None,
                      time_began=None,
                      distribution_type="ENCLAVE",
                      redact="NO"):
        """
        Submits a new report to TruSTAR station.

        :param title: Title of the report.
        :param report_body: Body of the report.
        :param enclave_ids: Enclave IDs where to submit the report.
        :param external_url: External URL of the report.
        :param time_began: Incident time. Defaults to current time if not given.
        :param distribution_type: Whether the report will be in the community, or only
        in enclaves
        :param redact: Wether to redact a report before submitting or not.

        :return: Entry context with the submitted report.
        """
        if distribution_type == 'ENCLAVE' and enclave_ids is None:
            raise Exception('Distribution type is ENCLAVE, but no enclave ID was given.')

        if redact == "YES":
            response = self.client.redact_report(
                title=title,
                report_body=report_body
            )

            title = response.title
            report_body = response.body

        ts_report = trustar.models.Report(
            title=title,
            body=report_body,
            enclave_ids=enclave_ids,
            is_enclave=(distribution_type == 'ENCLAVE'),
            time_began=time_began,
            external_url=external_url
        )

        response = self.client.submit_report(ts_report)
        report = ts_report.to_dict(remove_nones=True)
        report['reportDeepLink'] = self.get_report_deep_link(response.id)
        report['id'] = response.id
        ec = self.context_manager.get_reports_ec([report])
        title = 'TruSTAR report was successfully created'
        entry = self.get_entry(title, report, ec)
        return entry

    def delete_report(self, report_id=None, id_type=None):
        """
        Deletes report from TruStar.

        :param report_id: ID of the report to be deleted.
        :param id_type: Report id type. External or internal.

        :return: Success Message.
        """
        self.client.delete_report(report_id, id_type)
        return f'Report {report_id} was successfully deleted'

    def get_correlated_reports(self,
                               indicators=None,
                               enclave_ids=None,
                               distribution_type=None,
                               limit=None):
        """
        Returns a list of all reports that contain any of the provided
        indicator values.

        :param indicators: indicators list to perform the query.
        :param enclave_ids: enclaves list to restrict the query.
        :param distribution_type: Distribution type of the report.
        :param limit: Maximum value of report to be returned.

        :return: Entry context with found reports.
        """
        response = self.client.get_correlated_reports_page(
            indicators,
            enclave_ids,
            is_enclave=(distribution_type == "ENCLAVE"),
            page_number=0,
            page_size=limit
        )

        if not response:
            return 'No reports were found.'

        correlated_reports = []
        for report in response:
            current_report = report.to_dict(remove_nones=True)
            current_report.update(self.get_report_timestamps(current_report))
            correlated_reports.append(current_report)

        title = 'TruSTAR correlated reports'
        entry = self.get_entry(title, correlated_reports)
        return entry

    def get_report_details(self, report_id=None, id_type=None):
        """
        Finds a report by its ID and returns the report details.

        :param report_id: Report ID.
        :param id_type: Type of report ID. External or internal.

        :return: Entry context with Report queried.
        """
        response = self.client.get_report_details(report_id, id_type)
        if not response:
            return f"No details were found for report ID {report_id}"

        current_report_dict = response.to_dict(remove_nones=True)
        id = current_report_dict.get("id")
        current_report_dict.update(self.get_report_timestamps(current_report_dict))
        current_report_dict['reportDeepLink'] = self.get_report_deep_link(id)

        ec = self.context_manager.get_reports_ec([current_report_dict])

        title = f'TruSTAR report ID {report_id} details'
        entry = self.get_entry(title, current_report_dict, ec)
        return entry

    def update_report(self, **kwargs):
        """
        Update the report with the specified ID. Either the internal TruSTAR
        report ID or an external tracking ID can be used. Only the fields passed will
        be updated. All other fiels will remain unchanged.

        :return: Entry Context with updated report.
        """
        report_id = kwargs.pop('report_id')
        ts_report = self.client.get_report_details(report_id).to_dict()

        if kwargs.get('distribution_type'):
            kwargs["distributionType"] = kwargs.pop('distribution_type')

        if kwargs.get('report_body'):
            kwargs["reportBody"] = kwargs.pop('report_body')

        if kwargs.get('enclave_ids'):
            kwargs["enclaveIds"] = kwargs.pop('enclave_ids')

        if kwargs.get('external_url'):
            kwargs["externalUrl"] = kwargs.pop('external_url')

        if kwargs.get('time_began'):
            kwargs["timeBegan"] = kwargs.pop('time_began')

        ts_report.update(kwargs)
        self.client.update_report(Report.from_dict(ts_report))

        ts_report.update(self.get_report_timestamps(ts_report))
        ts_report['reportDeepLink'] = self.get_report_deep_link(report_id)
        ec = self.context_manager.get_reports_ec([ts_report])

        title = 'TruSTAR report was successfully updated'
        entry = self.get_entry(title, ts_report, ec)
        return entry

    def get_enclaves(self):
        """
        Returns the list of all enclaves that the user has access to, as
        well as whether they can read, create, and update reports in that enclave.

        :return: Entry context with list of enclaves
        """
        response = self.client.get_user_enclaves()
        enclaves, ec = self.context_manager.get_enclaves_ec(response)

        if not response:
            return "No enclaves were found."

        title = 'TruSTAR Enclaves'
        entry = self.get_entry(title, enclaves, ec)
        return entry

    def get_related_indicators(self, indicators=None, enclave_ids=None, limit=None):
        """
        Finds all reports that contain any of the given indicators
        and returns correlated indicators from those reports.

        :param indicators: list of indicator values.
        :param enclave_ids: list of enclaves to filter found reports.
        :param limit: Max num of related indicators to return.

        :return: Entry Context with related indicators.
        """
        related_indicator_response = self.client.get_related_indicators_page(
            indicators=indicators,
            enclave_ids=enclave_ids,
            page_size=limit,
            page_number=0
        )

        if not related_indicator_response:
            return f'No indicators related to {indicators} were found.'

        results = self.context_manager.get_indicators_context(related_indicator_response.items)
        return results

    def get_trending_indicators(self, indicator_type=None, days_back=None):
        """
        Find indicators that are trending in the community.

        :param indicator_type: Types of indicators to be returned. If is equal to 'other',
        then all indicator types except for CVE and MALWARE will be returned.
        :param days_back: The number of days back to count correlations for.

        """
        indicator_type = None if indicator_type == 'other' else indicator_type
        response = self.client.get_community_trends(indicator_type, days_back)

        if not response:
            return 'No trending indicators were found.'

        results = self.context_manager.get_indicators_context(response)
        return results

    def search_reports(self,
                       search_term=None,
                       enclave_ids=None,
                       from_time=None,
                       to_time=None,
                       tags=None,
                       excluded_tags=None,
                       limit=None):
        """
        Searches for all reports that contain the given search term.

        :param search_term: term to search for within the reports.
        :param enclave_ids: list of enclaves to restrict te search to.

        :return: Entry Context with Found reports.
        """
        from_time = Utils.date_to_unix(from_time) if from_time else from_time
        to_time = Utils.date_to_unix(to_time) if to_time else to_time
        response = self.client.search_reports_page(
            search_term=search_term,
            enclave_ids=enclave_ids,
            from_time=from_time,
            to_time=to_time,
            tags=tags,
            excluded_tags=excluded_tags,
            page_number=0,
            page_size=limit
        )
        if not response:
            return "No reports were found"

        reports = []
        for report in response:
            current_report = report.to_dict(remove_nones=True)
            current_report.update(self.get_report_timestamps(current_report))
            reports.append(current_report)

        ec = self.context_manager.get_reports_ec(reports)

        title = f'TruSTAR reports that contain the term {search_term}'
        entry = self.get_entry(title, reports, ec)
        return entry

    def add_to_whitelist(self, indicators=None):
        """
        Adds a list of indicators to the Company's whitelist.

        :param indicators: list of indicators to be whitelisted.

        :return: Message indicating if the request was successful or not.
        """
        response = self.client.add_terms_to_whitelist(indicators)
        if not response:
            return 'Indicator could not be added to the whitelist.'

        return f'{indicators} added to the whitelist successfully'

    def remove_from_whitelist(self, indicator=None, indicator_type=None):
        """
        Deletes an indicator from the Company's whitelist.

        :param indicator: Indicator to be deleted.
        :param indicator_type: type of the indicator to be deleted.

        :return: Message with the result of the request.
        """
        ts_indicator = Indicator(
            value=indicator,
            type=indicator_type
        )
        try:
            self.client.delete_indicator_from_whitelist(ts_indicator)
            return f'{indicator} removed from the whitelist successfully'
        except Exception:
            return 'Indicator could not be removed from the whitelist.'

    def get_indicators_metadata(self, indicators=None, enclave_ids=None):
        """
        Provide metadata associated with a list of indicators. The metadata is determined based on the
        enclaves the user making the request has READ access to.

        :param indicators: indicators list to search the corresponding metadata.
        :param enclave_ids: list of enclave IDs to restrict to. By default, uses all of the user’s enclaves.

        :return: Entry context with indicators metadata.
        """

        ts_indicators = [Indicator(value=i) for i in indicators]
        response = self.client.get_indicators_metadata(ts_indicators, enclave_ids)

        if not response:
            return 'No indicators metadata were found.'

        results = self.context_manager.get_indicators_context(response, "IndicatorsMetadata")
        return results

    def get_indicator_summaries(self, values=None, enclave_ids=None, limit=None):
        """
        Provides structured summaries about indicators, which are derived from
        intelligence sources on the TruSTAR Marketplace.

        :param values: list of indicator values to search on TruSTAR.
        :param enclave_ids: list of enclave_ids to restrict the query.
        :param limit: Maximum value of entries to return.

        :return: Entry Context with indicator summaries.
        """
        response = self.client.get_indicator_summaries_page(
            values,
            enclave_ids=enclave_ids,
            page_number=0,
            page_size=limit
        )

        if not response:
            return 'No indicator summaries were found.'

        results = self.context_manager.get_indicator_summaries_context(response.items, "IndicatorSummaries")
        return results

    def move_report(self, report_id=None, dest_enclave_id=None):
        """
        Moves report from one user enclave to another.

        :param report_id: Report ID.
        :dest_enclave_id: Enclave ID where the report will be moved.

        :return: Success Message.
        """
        response = self.client.move_report(report_id=report_id, dest_enclave_id=dest_enclave_id)
        return f"{response} has been moved to enclave id: {dest_enclave_id}"

    def copy_report(self, report_id=None, dest_enclave_id=None):
        """
        Copies report from one user enclave to another.

        :param report_id: Report ID.
        :dest_enclave_id: Enclave ID where the report will be moved.

        :return: Success Message.
        """

        response = self.client.copy_report(src_report_id=report_id, dest_enclave_id=dest_enclave_id)
        return f"{report_id} has been copied to enclave id: {dest_enclave_id} with id: {response}"

    def get_whitelist(self, limit=None):
        """
        Gets a list of indicators that the user’s company has whitelisted.

        :param limit: Maximum number of whitelisted indicators to return.
        :return: Entry context with whitelisted indicators.
        """

        response = self.client.get_whitelist_page(page_number=0, page_size=limit)
        if not response:
            return 'No Whitelist was found.'

        results = self.context_manager.get_indicators_context(response.items, 'WhitelistedIndicators')
        return results

    def get_indicators_for_report(self, report_id=None, limit=None):
        """
        Return a list of indicators extracted from a report.

        :param report_id: Report ID to extract indicators from.
        :param limit: Max number of indicators to return.

        :return: Entry context with extracted indicators.
        """

        response = self.client.get_indicators_for_report_page(
            report_id=report_id,
            page_number=0,
            page_size=limit
        )

        if not response:
            return f'No Indicators were found in report {report_id}.'

        results = self.context_manager.get_indicators_context(response.items)
        return results

    def get_all_phishing_indicators(self,
                                    priority_event_score=None,
                                    normalized_indicator_score=None,
                                    from_time=None,
                                    to_time=None,
                                    status=None,
                                    limit=None):
        """
        Get phishing indicators that match the given criteria.

        :param priority_event_score: A list with the scores to restrict the search to.
        :param normalized_indicator_score: A list with the scores to restrict the search to.
        :param from_time: Start of the polling window.
        :param to_time: End of the polling window.
        :param status: Status of the phishing indicatror.
        :param limit: Limit of results to return. Default is 25.

        :return: Entry Context with Phishing Indicators found.
        """
        args = {'priority_event_score': priority_event_score,
                'normalized_indicator_score': normalized_indicator_score,
                'status': status,
                'page_size': limit,
                'from_time': Utils.date_to_unix(from_time) if from_time else None,
                'to_time': Utils.date_to_unix(to_time) if to_time else None}
        response = self.client.get_phishing_indicators_page(**args)
        if not response:
            return 'No phishing indicators were found.'

        results = self.context_manager.get_indicators_context(response.items, 'PhishingIndicator')
        return results

    def get_phishing_submissions(self,
                                 priority_event_score=None,
                                 from_time=None,
                                 to_time=None,
                                 status=None,
                                 limit=None):
        """
        Fetches all phishing submissions that fit the given criteria.

        :param priority_event_score: List of scores to restrict the search to.
        :param from_time: Start of polling window.
        :param to_time: End of polling window.
        :param status: List of phishing submission status to restrict the search to.
        :param limit: Limit of results to return. Default is 25.

        :return: Entry Context with all phishing submissions found.
        """
        args = {'priority_event_score': priority_event_score,
                'status': status,
                'page_size': limit,
                'from_time': Utils.date_to_unix(from_time) if from_time else None,
                'to_time': Utils.date_to_unix(to_time) if to_time else None}
        response = self.client.get_phishing_submissions_page(**args)
        if not response.items:
            return 'No phishing submissions were found.'

        submissions, ec = self.context_manager.translate_triage_submission(response.items)
        title = 'TruSTAR phishing triage submissions'
        entry = self.get_entry(title, submissions, ec)
        return entry

    def set_triage_status(self, submission_id=None, status=None):
        """
        Marks a phishing email submission with one of the phishing namespace.

        :param submission_id: Phishing Submission ID.
        :param status: Submission status.

        :return: Request status message.
        """
        try:
            response = self.client.mark_triage_status(submission_id, status)
            response.raise_for_status()
            return f'Submission ID {submission_id} is {status}'
        except requests.exceptions.HTTPError as err:
            return str(err)

    def process(self, command, **kwargs):
        """
        Processes the command that the user has selected. Retrieves the params and converts
        them to the methods params syntax. Then makes the call to the helper method of the
        corresponding command and return the results. It puts data on the corresponding context and
        it also shows the data on the War room.
        """
        func = self.command_dict.get(command)
        args = {k.replace("-", "_"): v for k, v in kwargs.items()}
        list_args = {k: argToList(v) for k, v in args.items() if k in self.LIST_ARGS}
        args.update(list_args)
        result = func(**args)
        return return_results(result)


def main():
    """ PARSE AND VALIDATE INTEGRATION PARAMS """

    server = demisto.params().get('server')
    station = demisto.params().get('station')
    api_key = str(demisto.params().get('key'))
    api_secret = str(demisto.params().get('secret'))
    base_url = server + '/api/1.3' if server else None
    insecure = not demisto.params().get('insecure', False)

    LOG(f'command is {demisto.command()}')

    config = {
        'user_api_key': api_key,
        'user_api_secret': api_secret,
        'api_endpoint': base_url,
        'verify': insecure,
        'client_type': "Python_SDK",
        'client_metatag': "demisto-xsoar"
    }

    try:
        client = TrustarClient(config, station)
        client.process(demisto.command(), **demisto.args())

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return_error("Invalid Credentials. Please check your API Key and "
                         "Secret are correct on TruSTAR Station. Settings > API")

        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
