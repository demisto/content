import logging
import warnings
import google.auth
from pprint import pformat
from pandas.core.frame import DataFrame, Series
from google.cloud.bigquery.client import Client
from google.cloud import bigquery
from datetime import timedelta
from typing import List, Dict

import Tests.Marketplace.marketplace_services as mp_services
from Tests.Marketplace.marketplace_constants import Metadata, LANDING_PAGE_SECTIONS_PATH


class PackStatisticsHandler:
    """" A class that manipulates the needed statistics of a given pack.

    Attributes:
        pack_name (str): The pack name.
        _packs_dc_desc (Series): A pandas Series of packs sorted descending by download count
        _packs_statistics_df (DataFrame): The pandas statistics dataframe.
        download_count (int): The pack's downloads count.

    """

    def __init__(self, pack_name, packs_statistics_df: DataFrame, packs_download_count_desc: Series,
                 displayed_dependencies: list):
        self.pack_name: str = pack_name
        self._packs_statistics_df: DataFrame = packs_statistics_df
        self._packs_dc_desc: Series = packs_download_count_desc
        self._displayed_dependencies = displayed_dependencies
        self.displayed_dependencies_sorted: list = self._get_pack_dependencies_sorted()
        self.download_count: int = self._get_pack_downloads_count()

    def _get_pack_dependencies_sorted(self):
        """ Filters the packs download count series by the pack dependencies

        Returns:
            list: pack names that are dependencies of the current pack by descending download count

        """
        full_series_index = self._packs_dc_desc.index
        packs_dependencies_sorted_series = self._packs_dc_desc.loc[full_series_index.isin(self._displayed_dependencies)]
        packs_dependencies_sorted = list(packs_dependencies_sorted_series.index.array)
        # Adds a new packs that does not yet exist in the market place
        for dep_pack_name in self._displayed_dependencies:
            if dep_pack_name not in packs_dependencies_sorted:
                packs_dependencies_sorted.append(dep_pack_name)

        logging.info(f'{self.pack_name} pack sorted dependencies: {packs_dependencies_sorted}')
        return packs_dependencies_sorted

    def _get_pack_downloads_count(self):
        """ Returns number of packs downloads from big query dataframe.

        Returns:
            int: number of packs downloads.
        """
        downloads_count = 0
        if self.pack_name in self._packs_dc_desc:
            downloads_count = int(self._packs_dc_desc[self.pack_name])

        return downloads_count

    @staticmethod
    def calculate_search_rank(tags, certification, content_items):
        """ Returns pack search rank.

        The initial value is 0
        In case the pack has the tag Featured, its search rank will increase by 10
        In case the pack was released in the last 30 days, its search rank will increase by 10
        In case the pack is certified, its search rank will increase by 10
        In case all the pack's integration are deprecated and there is at least 1 integration in the pack,
        the pack's search rank will decrease by 50

        Args:
            tags (set): the pack's tags.
            certification (str): certification value from pack_metadata, if exists.
            content_items (dict): all the pack's content items, including integrations info

        Returns:
            str: certification value
        """
        search_rank = 0
        all_deprecated = False

        if 'Featured' in tags:
            search_rank += 10
        if 'New' in tags:
            search_rank += 10
        if certification == Metadata.CERTIFIED:
            search_rank += 10

        if content_items:
            integrations = content_items.get('integration')
            if isinstance(integrations, list):
                for integration in integrations:
                    if 'deprecated' in integration.get('name').lower():
                        all_deprecated = True
                    else:
                        all_deprecated = False
                        break

        if all_deprecated:
            search_rank -= 50

        return search_rank


class StatisticsHandler:
    """" A class that handles all-packs related statistics.

    Attributes:
        _bq_client (google.cloud.bigquery.client.Client): The Google Big-Query client.
        _index_folder_path (str): The index root folder path.
        packs_statistics_df (DataFrame): All packs statistics dataframe from Google Big-Query.
        landing_page_sections (list): Marketplace landing page sections.
        trending_packs (list): A list of trending packs.

    """

    DOWNLOADS_TABLE = "oproxy-dev.shared_views.top_packs"  # packs downloads statistics table
    TOP_PACKS_14_DAYS_TABLE = 'oproxy-dev.shared_views.top_packs_14_days'
    BIG_QUERY_MAX_RESULTS = 2000  # big query max row results

    def __init__(self, service_account: str, index_folder_path: str):
        self._bq_client: Client = init_bigquery_client(service_account)
        self._index_folder_path: str = index_folder_path
        self.packs_statistics_df: DataFrame = self._get_packs_statistics_df()
        self.packs_download_count_desc: Series = self.packs_statistics_df.num_count.sort_values(ascending=False).\
            astype('int32')
        self.landing_page_sections = self.get_landing_page_sections()
        self.trending_packs = self._get_trending_packs()

    def _get_packs_statistics_df(self) -> DataFrame:
        """ Runs big query, selects all columns from top_packs table and returns table as pandas data frame.
        Additionally table index is set to pack_name (pack unique id).


        Returns:
            downloads statistics table dataframe.
        """
        query = f"SELECT * FROM `{StatisticsHandler.DOWNLOADS_TABLE}` LIMIT {StatisticsHandler.BIG_QUERY_MAX_RESULTS}"
        # ignore missing package warning
        warnings.filterwarnings("ignore", message="Cannot create BigQuery Storage client, the dependency ")
        packs_statistic_table = self._bq_client.query(query).result().to_dataframe()
        packs_statistic_table.set_index('pack_name', inplace=True)

        return packs_statistic_table

    @staticmethod
    def get_landing_page_sections() -> Dict:
        """ Returns the landing page sections file content """
        return mp_services.load_json(LANDING_PAGE_SECTIONS_PATH)

    def _filter_packs_from_before_3_months(self, pack_list_to_filter: list) -> List[str]:
        """
        Filtering packs from 'pack_list_to_filter' that were created more than 3 months ago by checking in the index file
        Args:
            pack_list_to_filter: The list of packs sorted by download rate to filter by creation date.

        Returns:
            A list with pack names that were created within the last 3 months.
        """
        three_months_delta = timedelta(days=90)
        filtered_packs_list = []

        for pack_name in pack_list_to_filter:
            if mp_services.Pack.pack_created_in_time_delta(pack_name, three_months_delta, self._index_folder_path):
                filtered_packs_list.append(pack_name)

        logging.debug(f'packs with less than 3 months creation time: {pformat(filtered_packs_list)}')
        return filtered_packs_list

    def _get_trending_packs(self) -> list:
        """
        Updates the landing page sections data with Trending packs.
        Trending packs: top 20 downloaded packs in the last 14 days.

        Returns:
            A list with 20 pack names that has the highest download rate.
        """
        query = f"SELECT pack_name FROM `{StatisticsHandler.TOP_PACKS_14_DAYS_TABLE}` ORDER BY num_count DESC"
        packs_sorted_by_download_count_dataframe = self._bq_client.query(query).result().to_dataframe()
        packs_sorted_by_download_count = [
            pack_array[0] for pack_array in packs_sorted_by_download_count_dataframe.to_numpy()
        ]
        filtered_pack_list = self._filter_packs_from_before_3_months(packs_sorted_by_download_count)
        top_downloaded_packs = filtered_pack_list[:20]

        current_iteration_index = 0
        while len(top_downloaded_packs) < 20:
            current_pack = packs_sorted_by_download_count[current_iteration_index]
            if current_pack not in top_downloaded_packs:
                top_downloaded_packs.append(current_pack)
            current_iteration_index += 1

        logging.debug(f'Found the following trending packs {pformat(top_downloaded_packs)}')
        return top_downloaded_packs


# ========== HELPER FUNCTIONS ==========

def init_bigquery_client(service_account=None):
    """Initialize google cloud big query client.

    In case of local dev usage the client will be initialized with user default credentials.
    Otherwise, client will be initialized from service account json that is stored in CirlceCI.

    Args:
        service_account (str): full path to service account json.

    Return:
         google.cloud.bigquery.client.Client: initialized google cloud big query client.
    """
    if service_account:
        bq_client = bigquery.Client.from_service_account_json(service_account)
        logging.info("Created big query service account")
    else:
        # in case of local dev use, ignored the warning of non use of service account.
        warnings.filterwarnings("ignore", message=google.auth._default._CLOUD_SDK_CREDENTIALS_WARNING)
        credentials, project = google.auth.default()
        bq_client = bigquery.Client(credentials=credentials, project=project)
        logging.info("Created big query private account")

    return bq_client
