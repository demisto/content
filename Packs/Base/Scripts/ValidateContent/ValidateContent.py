from demisto_sdk.commands.validate.validators.base_validator import InvalidContentItemResult, ValidationResult, ValidationCaughtExceptionResult, \
    BaseValidator
from pydantic.errors import ConfigError
from pydantic.utils import ROOT_KEY

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import io
import json
import traceback
import types
import zipfile
from base64 import b64decode
from contextlib import redirect_stderr
from datetime import datetime
from pathlib import Path
from shutil import copy
from tempfile import TemporaryDirectory, TemporaryFile
from typing import Any, Dict, List, Optional, Tuple, Set

import git
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, TYPE_TO_EXTENSION, FileType, ExecutionMode
from demisto_sdk.commands.common.content import Content
from demisto_sdk.commands.common.logger import logging_setup
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.init.contribution_converter import (
    AUTOMATION, INTEGRATION, INTEGRATIONS_DIR, SCRIPT, SCRIPTS_DIR,
    ContributionConverter, get_child_directories, get_child_files)
from demisto_sdk.commands.lint.lint_manager import LintManager
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from demisto_sdk.commands.validate.validation_results import (
    ResultWriter,
)
from demisto_sdk.commands.validate.initializer import Initializer

from ruamel.yaml import YAML

from demisto_sdk.commands.content_graph.objects.base_content import (BaseContent, CONTENT_TYPE_TO_MODEL)
from demisto_sdk.commands.validate.config_reader import (
    ConfigReader,
    ConfiguredValidations,
)
from demisto_sdk.commands.common.logger import logger

CACHED_MODULES_DIR = '/tmp/cached_modules'
yaml = YAML()

##############################################################################################################################

from pydantic import BaseModel, validate_model
from typing import Type, Any

object_setattr = object.__setattr__


def new_from_orm(cls, obj):
    demisto.debug("Entering new_from_orm method")

    if not cls.__config__.orm_mode:
        demisto.error("ConfigError: orm_mode must be set to True to use from_orm")
        raise ConfigError('You must have the config attribute orm_mode=True to use from_orm')

    demisto.debug(f"orm_mode is enabled for class {cls.__name__=}")

    obj = {ROOT_KEY: obj} if cls.__custom_root_type__ else cls._decompose_class(obj)
    # demisto.debug(f"Object decomposed: {obj=}")

    m = cls.__new__(cls)
    demisto.debug(f"New instance of class {cls.__name__=} created")
    demisto.debug(f"Attributes of the instance: {dir(m)=}")
    demisto.debug(f'#########################')
    demisto.debug(f'{m.__validators__=}')
    demisto.debug(f'{m.__get_validators__=}')
    demisto.debug(f'{m.__pre_root__validators__=}')
    demisto.debug(f'{m.__post_root_validators__=}')
    demisto.debug(f'#########################')

    demisto.debug(f"Passing model {cls.__name__} and object {obj=} to validate_model")
    values, fields_set, validation_error = validate_model(cls, obj)
    demisto.debug(f"Model validated. Values: {values=}, Fields set:{fields_set}")

    if validation_error:
        demisto.error(f"Validation error: {validation_error=}")
        raise validation_error

    object_setattr(m, '__dict__', values)
    object_setattr(m, '__fields_set__', fields_set)
    demisto.debug(f"Attributes set on the instance of class {cls.__name__=}")

    m._init_private_attributes()
    demisto.debug(f"Private attributes initialized for instance of class {cls.__name__=}")

    demisto.debug("Exiting new_from_orm method")
    return m


BaseModel.from_orm = classmethod(new_from_orm)



##############################################################################################################################
class CustomResultsWriter(ResultWriter):
    def post_results(
        self,
        only_throw_warning: Optional[List[str]] = None,
    ) -> int:
        """
            Go through the validation results list,
            posting the warnings / failure message for failed validation,
            and calculates the exit_code.

        Returns:
            int: The exit code number - 1 if the validations failed, otherwise return 0
        """
        fixed_objects_set: Set[BaseContent] = set()
        exit_code = 0
        if self.json_file_path:
            self.write_results_to_json_file()
        for result in self.validation_results:
            if only_throw_warning and result.validator.error_code in only_throw_warning:
                demisto.debug(f"<yellow>{result.format_readable_message}</yellow>")
            else:
                demisto.error(f"<red>{result.format_readable_message}</red>")
                exit_code = 1
        for fixing_result in self.fixing_results:
            fixed_objects_set.add(fixing_result.content_object)
            if (
                not only_throw_warning
                or fixing_result.validator.error_code not in only_throw_warning
            ):
                exit_code = 1
            demisto.debug(f"<yellow>{fixing_result.format_readable_message}</yellow>")
        for result in self.invalid_content_item_results:
            demisto.error(f"<red>{result.format_readable_message}</red>")
            exit_code = 1
        for result in self.validation_caught_exception_results:
            demisto.error(f"<red>{result.format_readable_message}</red>")
            exit_code = 1
        if not exit_code:
            demisto.info("<green>All validations passed.</green>")
        for fixed_object in fixed_objects_set:
            fixed_object.save()
        return exit_code

    def write_results_to_json_file(self):
        """
        If the json path argument is given,
        Writing all the results into a json file located in the given path.
        """
        json_validations_list = [
            result.format_json_message for result in self.validation_results
        ]
        demisto.debug(f'write_results_to_json_file {json_validations_list=}')
        json_fixing_list = [
            fixing_result.format_json_message for fixing_result in self.fixing_results
        ]
        demisto.debug(f'write_results_to_json_file {json_fixing_list=}')
        json_invalid_content_item_list = [
            result.format_json_message for result in self.invalid_content_item_results
        ]
        demisto.debug(f'write_results_to_json_file {json_invalid_content_item_list=}')
        json_validation_caught_exception_list = [
            result.format_json_message
            for result in self.validation_caught_exception_results
        ]
        demisto.debug(f'write_results_to_json_file {json_validation_caught_exception_list=}')

        results = {
            "validations": json_validations_list,
            "fixed validations": json_fixing_list,
            "invalid content items": json_invalid_content_item_list,
            "Validations that caught exceptions": json_validation_caught_exception_list,
        }
        json_object = json.dumps(results, indent=4)
        demisto.debug(f'write_results_to_json_file: {json_object}')

        demisto.debug(f'write_results_to_json_file writing to json_file: {self.json_file_path}')
        # Writing to sample.json
        with open(self.json_file_path, "w") as outfile:
            outfile.write(json_object)
        demisto.debug(f'write_results_to_json_file writing to json_file: Success!')

##############################################################################################################################
from demisto_sdk.commands.common.content_constant_paths import CONTENT_PATH


def new_format_message(self):
    try:
        relative_file_path: str = str(self.content_object.path.relative_to(CONTENT_PATH))
        demisto.debug(f'new_format_message try: {relative_file_path=}')
    except ValueError:
        relative_file_path = str(self.content_object.path)
        demisto.debug(f'new_format_message except: {relative_file_path=}')

    return {
        "file path": relative_file_path,
        "error code": self.validator.error_code,
        "message": self.message,
    }

def format_readable_message(self):
    path: Path = self.content_object.path
    if path.is_absolute():
        try:
            path = path.relative_to(CONTENT_PATH)
            demisto.debug(f'BaseValidator format_readable_message try: {path=}')
        except ValueError:
            demisto.debug(f'BaseValidator format_readable_message except: {path=}')
    return f"{str(path)}: [{self.validator.error_code}] - {self.message}"


BaseValidator.format_json_message = property(new_format_message)
BaseValidator.format_readable_message = property(format_readable_message)


def new_invalid_content_item_format_message(self):
    try:
        relative_file_path: str = str(self.path.relative_to(CONTENT_PATH))
        demisto.debug(f'new_invalid_content_item_format_message try: {relative_file_path=}')
    except ValueError:
        relative_file_path = str(self.path)
        demisto.debug(f'new_invalid_content_item_format_message except: {relative_file_path=}')

    return {
        "file path": relative_file_path,
        "error code": self.error_code,
        "message": self.message,
    }

def format_readable_message(self):
    path: Path = self.path
    if path.is_absolute():
        try:
            path = path.relative_to(CONTENT_PATH)
            demisto.debug(f'InvalidContentItemResult format_readable_message try: {path=}')
        except ValueError:
            demisto.debug(f'InvalidContentItemResult format_readable_message except: {path=}')
        return f"{path}: [{self.error_code}] - {self.message}"


InvalidContentItemResult.format_readable_message = property(format_readable_message)
InvalidContentItemResult.format_json_message = property(new_invalid_content_item_format_message)

##############################################################################################################################
from demisto_sdk.commands.content_graph.parsers.content_item import (
    ContentItemParser,
    IncorrectParserException
)

from demisto_sdk.commands.common.constants import (
    MARKETPLACE_MIN_VERSION,
    PACK_DEFAULT_MARKETPLACES,
    MarketplaceVersions,
)


class CustomContentItemParser(ContentItemParser):

    @staticmethod
    def from_path(
        path: Path,
        pack_marketplaces: List[MarketplaceVersions] = list(MarketplaceVersions),
        git_sha: Optional[str] = None,
    ) -> ContentItemParser:
        """Tries to parse a content item by its path.
        If during the attempt we detected the file is not a content item, `None` is returned.

        Returns:
            Optional[ContentItemParser]: The parsed content item.
        """
        from demisto_sdk.commands.content_graph.common import ContentType

        demisto.debug(f"Parsing content item {path} | {git_sha=}")
        if not ContentItemParser.is_content_item(path):
            if ContentItemParser.is_content_item(path.parent):
                path = path.parent
        try:
            content_type: ContentType = ContentType.by_path(path)
        except ValueError:
            try:
                optional_content_type = ContentType.by_schema(path, git_sha=git_sha)
            except ValueError as e:
                demisto.error(f"Could not determine content type for {path}: {e}")
                raise InvalidContentItemException from e
            content_type = optional_content_type
        if parser_cls := ContentItemParser.content_type_to_parser.get(content_type):
            try:
                return CustomContentItemParser.parse(
                    parser_cls, path, pack_marketplaces, git_sha
                )
            except IncorrectParserException as e:
                return CustomContentItemParser.parse(
                    e.correct_parser, path, pack_marketplaces, git_sha, **e.kwargs
                )
            except NotAContentItemException:
                demisto.debug(f"{path} is not a content item, skipping")
                raise
            except Exception as e:
                demisto.error(f"Failed to parse {path}: {e}")
                raise InvalidContentItemException from e
        demisto.debug(f"Could not find parser for {content_type} of {path}")
        raise NotAContentItemException


##############################################################################################################################
from typing import Type
from demisto_sdk.commands.content_graph.common import (
    ContentType,
)
from functools import cached_property, lru_cache

from demisto_sdk.commands.content_graph.parsers import content_item

from demisto_sdk.commands.common.constants import (
    MARKETPLACE_MIN_VERSION,
    PACKS_FOLDER,
    PACKS_PACK_META_FILE_NAME,
    GitStatuses,
    MarketplaceVersions,
)
from demisto_sdk.commands.content_graph.parsers.pack import PackParser


class CustomBaseContent(BaseContent):
    @staticmethod
    @lru_cache
    def from_path(
        path: Path,
        git_sha: Optional[str] = None,
        raise_on_exception: bool = False,
        metadata_only: bool = False,
    ) -> Optional["BaseContent"]:
        demisto.debug(f"Loading content item from {path}")

        if (
            path.is_dir()
            and path.parent.name == PACKS_FOLDER
            or path.name == PACKS_PACK_META_FILE_NAME
        ):  # if the path given is a pack
            try:

                return CONTENT_TYPE_TO_MODEL[ContentType.PACK].from_orm(
                    PackParser(path, git_sha=git_sha, metadata_only=metadata_only)
                )
            except InvalidContentItemException:
                demisto.error(f"Could not parse content from {path}")
                return None

        try:
            content_item.MARKETPLACE_MIN_VERSION = "0.0.0"
            demisto.debug(f'################################# CustomContentItemParser.from_path({path}, {git_sha=})')
            content_item_parser = CustomContentItemParser.from_path(path, git_sha=git_sha)
            content_item.MARKETPLACE_MIN_VERSION = MARKETPLACE_MIN_VERSION

        except (NotAContentItemException, InvalidContentItemException) as e:
            if raise_on_exception:
                raise
            demisto.error(
                f"Invalid content path provided: {path}. Please provide a valid content item or pack path. ({type(e).__name__})"
            )
            return None

        demisto.debug(f'from_path {content_item_parser.content_type=} | {CONTENT_TYPE_TO_MODEL=}')
        model = CONTENT_TYPE_TO_MODEL.get(content_item_parser.content_type)
        if model:
            demisto.debug(f"Detected model {model} for {path.name}")
        else:
            demisto.error(f"Could not parse content item from {path.name}")
            return None

        try:
            import inspect
            source_code = inspect.getsource(model.from_orm)
            demisto.debug(f"Source code of {model.from_orm.__name__=}:\n{source_code=}")
        except Exception as e:
            demisto.error(f"Could not retrieve source code for {model.from_orm.__name__=}: {e=}")

            return model.from_orm(content_item_parser)  # type: ignore
        except Exception as e:
            demisto.error(
                f"Could not parse content item from path {path} using {content_item_parser} | {str(e)} | {str(traceback.format_exc())}"
            )

            # Log the error message
            demisto.error(f"Error: {str(e)}")

            # Log the detailed stack trace
            demisto.error("Stack Trace: " + traceback.format_exc())
            traceback.print_exc()

        return None


##############################################################################################################################
from demisto_sdk.commands.content_graph.objects.repository import (
    ContentDTO,
)
from demisto_sdk.commands.content_graph.parsers.content_item import (
    InvalidContentItemException,
    NotAContentItemException,
)


class CustomInitializer(Initializer):

    def paths_to_basecontent_set(
        self, files_set: Set[Path]
    ) -> tuple[set[BaseContent], set[Path], set[Path]]:
        """Attempting to convert the given paths to a set of BaseContent.

        Args:
            files_set (Path): The set of file paths to case into BaseContent.

        Returns:
            Tuple[Set[BaseContent], Set[Path], Set[Path]]: The sets of all the successful casts, the sets of all failed casts, and the set of non content items.
        """
        basecontent_with_path_set: Set[BaseContent] = set()
        invalid_content_items: Set[Path] = set()
        non_content_items: Set[Path] = set()
        related_files_main_items: Set[Path] = self.collect_related_files_main_items(
            files_set
        )
        demisto.debug(f'paths_to_basecontent_set {related_files_main_items=}')
        for file_path in related_files_main_items:
            path: Path = Path(file_path)
            demisto.debug(f'paths_to_basecontent_set {path=}')
            try:
                temp_obj = CustomBaseContent.from_path(
                    path, git_sha=None, raise_on_exception=True
                )
                demisto.debug(f'paths_to_basecontent_set {temp_obj=}')
                if temp_obj is None:
                    invalid_content_items.add(path)
                else:
                    basecontent_with_path_set.add(temp_obj)
            except NotAContentItemException:
                non_content_items.add(file_path)  # type: ignore[arg-type]
            except InvalidContentItemException:
                invalid_content_items.add(file_path)  # type: ignore[arg-type]
            except Exception as e:
                demisto.debug(f'paths_to_basecontent_set {str(e)=}')
        return basecontent_with_path_set, invalid_content_items, non_content_items

    def gather_objects_to_run_on(
        self,
    ) -> Tuple[Set[BaseContent], Set[Path]]:
        """
        Filter the file that should run according to the given flag (-i/-g/-a).

        Returns:
            Tuple[Set[BaseContent], Set[Path]]: The sets of all the successful casts, and the sets of all failed casts.
        """
        content_objects_to_run: Set[BaseContent] = set()
        invalid_content_items: Set[Path] = set()
        non_content_items: Set[Path] = set()
        if self.execution_mode == ExecutionMode.USE_GIT:
            (
                content_objects_to_run,
                invalid_content_items,
                non_content_items,
            ) = self.get_files_using_git()
        elif self.execution_mode == ExecutionMode.SPECIFIC_FILES:

            file_path = self.file_path.split(",")
            demisto.debug(f'gather_objects_to_run_on {file_path=}')
            loaded_files = set(self.load_files(file_path))
            demisto.debug(f'gather_objects_to_run_on {loaded_files=}')
            (
                content_objects_to_run,
                invalid_content_items,
                non_content_items,
            ) = self.paths_to_basecontent_set(loaded_files)

        elif self.execution_mode == ExecutionMode.ALL_FILES:
            demisto.debug("Running validation on all files.")
            content_dto = ContentDTO.from_path()
            if not isinstance(content_dto, ContentDTO):
                raise Exception("no content found")
            content_objects_to_run = set(content_dto.packs)
        else:
            self.execution_mode = ExecutionMode.USE_GIT
            self.committed_only = True
            (
                content_objects_to_run,
                invalid_content_items,
                non_content_items,
            ) = self.get_files_using_git()

        if self.execution_mode != ExecutionMode.USE_GIT:
            content_objects_to_run_with_packs: Set[BaseContent] = (
                self.get_items_from_packs(content_objects_to_run)
            )
        else:
            content_objects_to_run_with_packs = content_objects_to_run

        for non_content_item in non_content_items:
            demisto.debug(
                f"Invalid content path provided: {str(non_content_item)}. Please provide a valid content item or pack path."
            )
        return content_objects_to_run_with_packs, invalid_content_items


##############################################################################################################################


class CustomValidateManger(ValidateManager):
    def __init__(
        self,
        validation_results: ResultWriter,
        config_reader: ConfigReader,
        initializer: Initializer,
        file_path=None,
        allow_autofix=False,
        ignore_support_level=False,
        ignore: Optional[List[str]] = None,
    ):
        self.ignore_support_level = ignore_support_level
        self.file_path = file_path
        self.allow_autofix = allow_autofix
        self.validation_results = validation_results
        self.config_reader = config_reader
        self.initializer = initializer
        self.objects_to_run: Set[BaseContent] = set()
        self.invalid_items: Set[Path] = set()
        demisto.debug(f'CustomValidateManger __init__ {self.file_path=} | {self.initializer.file_path=}')
        (
            self.objects_to_run,
            self.invalid_items,
        ) = self.initializer.gather_objects_to_run_on()
        demisto.debug(f'CustomValidateManger __init__ {self.objects_to_run=} | {self.invalid_items=}')
        self.committed_only = self.initializer.committed_only
        self.configured_validations: ConfiguredValidations = self.config_reader.read(
            ignore_support_level=ignore_support_level,
            mode=self.initializer.execution_mode,
            codes_to_ignore=ignore,
        )
        self.validators = self.filter_validators()
        demisto.debug(f'CustomValidateManger __init__ {self.validators=}')

    def run_validations(self) -> int:
        """
            Running all the relevant validation on all the filtered files based on the should_run calculations,
            calling the fix method if the validation fail, has an autofix, and the allow_autofix flag is given,
            and calling the post_results at the end.
        Returns:
            int: the exit code to obtained from the calculations of post_results.
        """
        demisto.info("Starting validate items.")
        for validator in self.validators:
            demisto.debug(f"Starting execution for {validator.error_code} validator.")
            if filtered_content_objects_for_validator := list(
                filter(
                    lambda content_object: validator.should_run(
                        content_item=content_object,
                        ignorable_errors=self.configured_validations.ignorable_errors,
                        support_level_dict=self.configured_validations.support_level_dict,
                        running_execution_mode=self.initializer.execution_mode,
                    ),
                    self.objects_to_run,
                )
            ):
                validation_results: List[ValidationResult] = (
                    validator.obtain_invalid_content_items(
                        filtered_content_objects_for_validator
                    )
                )  # type: ignore
                if (
                    validator.expected_execution_mode == [ExecutionMode.ALL_FILES]
                    and self.initializer.execution_mode == ExecutionMode.ALL_FILES
                ):
                    validation_results = [
                        validation_result
                        for validation_result in validation_results
                        if validation_result.content_object
                           in filtered_content_objects_for_validator
                    ]
                try:
                    if self.allow_autofix and validator.is_auto_fixable:
                        for validation_result in validation_results:
                            try:
                                self.validation_results.append_fix_results(
                                    validator.fix(validation_result.content_object)  # type: ignore
                                )
                            except Exception:
                                demisto.error(
                                    f"Could not fix {validation_result.validator.error_code} error for content item {str(validation_result.content_object.path)}"
                                )
                                self.validation_results.append_validation_results(
                                    validation_result
                                )
                    else:
                        self.validation_results.extend_validation_results(
                            validation_results
                        )
                except Exception as e:
                    validation_caught_exception_result = ValidationCaughtExceptionResult(
                        message=f"Encountered an error when validating {validator.error_code} validator: {e}"
                    )
                    self.validation_results.append_validation_caught_exception_results(
                        validation_caught_exception_result
                    )
        if BaseValidator.graph_interface:
            logger.info("Closing graph.")
            BaseValidator.graph_interface.close()
        self.add_invalid_content_items()
        return self.validation_results.post_results(
            only_throw_warning=self.configured_validations.warning
        )


def _create_pack_base_files(self):
    """
    Create empty 'README.md', '.secrets-ignore', and '.pack-ignore' files that are expected
    to be in the base directory of a pack
    """
    fp = open(os.path.join(self.pack_dir_path, 'README.md'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.secrets-ignore'), 'a')
    fp.close()

    fp = open(os.path.join(self.pack_dir_path, '.pack-ignore'), 'a')
    fp.close()


def get_extracted_code_filepath(extractor: YmlSplitter) -> str:
    output_path = extractor.get_output_path()
    base_name = os.path.basename(output_path) if not extractor.base_name else extractor.base_name
    code_file = f'{output_path}/{base_name}'
    script = extractor.yml_data['script']
    lang_type: str = script['type'] if extractor.file_type == 'integration' else extractor.yml_data['type']
    code_file = f'{code_file}{TYPE_TO_EXTENSION[lang_type]}'
    return code_file


def content_item_to_package_format(
    self, content_item_dir: str, del_unified: bool = True, source_mapping: Optional[Dict] = None,  # noqa: F841
    code_fp_to_row_offset: Dict = {}
) -> None:
    child_files = get_child_files(content_item_dir)
    for child_file in child_files:
        cf_name_lower = os.path.basename(child_file).lower()
        if cf_name_lower.startswith((SCRIPT, AUTOMATION, INTEGRATION)) and cf_name_lower.endswith('yml'):
            content_item_file_path = child_file
            file_type = find_type(content_item_file_path)
            file_type = file_type.value if file_type else file_type
            try:
                extractor = YmlSplitter(
                    input=content_item_file_path, file_type=file_type, output=content_item_dir, no_logging=True,
                    no_pipenv=True, no_basic_fmt=True)
                extractor.extract_to_package_format()
                code_fp = get_extracted_code_filepath(extractor)
                code_fp_to_row_offset[code_fp] = extractor.lines_inserted_at_code_start
            except Exception as e:
                err_msg = f'Error occurred while trying to split the unified YAML "{content_item_file_path}" ' \
                          f'into its component parts.\nError: "{e}"'
                self.contrib_conversion_errs.append(err_msg)
            if del_unified:
                os.remove(content_item_file_path)


def convert_contribution_to_pack(contrib_converter: ContributionConverter) -> Dict:
    """Create or updates a pack in the content repo from the contents of a contribution zipfile

    Args:
        contrib_converter (ContributionConverter): Contribution contributor object
    """
    # only create pack_metadata.json and base pack files if creating a new pack
    if contrib_converter.create_new:
        if contrib_converter.contribution:
            # create pack metadata file
            with zipfile.ZipFile(contrib_converter.contribution) as zipped_contrib:
                with zipped_contrib.open('metadata.json') as metadata_file:
                    metadata = json.loads(metadata_file.read())
                    contrib_converter.create_metadata_file(metadata)
        # create base files
        contrib_converter.create_pack_base_files = types.MethodType(_create_pack_base_files, contrib_converter)
        contrib_converter.create_pack_base_files()
    # unpack
    contrib_converter.unpack_contribution_to_dst_pack_directory()
    # convert
    unpacked_contribution_dirs = get_child_directories(contrib_converter.pack_dir_path)
    for unpacked_contribution_dir in unpacked_contribution_dirs:
        contrib_converter.convert_contribution_dir_to_pack_contents(unpacked_contribution_dir)
    # extract to package format
    code_fp_to_row_offset: Dict[str, int] = {}
    for pack_subdir in get_child_directories(contrib_converter.pack_dir_path):
        basename = os.path.basename(pack_subdir)
        if basename in {SCRIPTS_DIR, INTEGRATIONS_DIR}:
            contrib_converter.content_item_to_package_format = types.MethodType(content_item_to_package_format,
                                                                                contrib_converter)
            contrib_converter.content_item_to_package_format(
                pack_subdir, del_unified=True, source_mapping=None, code_fp_to_row_offset=code_fp_to_row_offset
            )
    return code_fp_to_row_offset


def get_pack_name(zip_fp: str) -> str:
    """returns the pack name from the zipped contribution file's metadata.json file"""
    with zipfile.ZipFile(zip_fp) as zipped_contrib:
        with zipped_contrib.open('metadata.json') as metadata_file:
            metadata = json.loads(metadata_file.read())
    return metadata.get('name', 'ServerSidePackValidationDefaultName')


def adjust_linter_row_and_col(
    error_output: Dict, code_fp_to_row_offset: Optional[Dict] = None,
    row_offset: int = 2, row_start: int = 1, col_offset: int = 1, col_start: int = 0
) -> None:
    """Update the linter errors row and column numbering

    Accounts for lines inserted during demisto-sdk extract, and that row numbering starts with one. We
    take the max between the adjusted vector number and the vector start because the lowest the adjusted
    vector number should be is its associated vector start number. e.g. the adjusted column number should
    never be less than the column start number aka zero - so if the adjusted column number is -1, we set
    it to the column start number instead, aka zero.

    Args:
        error_output (Dict): A single validation result dictionary (validate and lint) from the total list
        code_fp_to_row_offset (Optional[Dict]): Mapping of file paths to the row offset for that code file
        row_offset (int): The number of rows to adjust by
        row_start (int): The lowest allowable number for rows
        col_offset (int): The number of columns to adjust by
        col_start (int): The lowest allowable number for columns
    """
    row, col = 'row', 'col'
    vector_details = [
        (row, row_offset, row_start),
        (col, col_offset, col_start)
    ]
    try:
        for vector, offset, start in vector_details:
            if vector in error_output:
                # grab and set the row offset from the file to row offset mapping if it exists and we are
                # operating on 'row'
                if code_fp_to_row_offset and vector == row:
                    filepath = error_output.get('filePath', '')
                    if filepath in code_fp_to_row_offset:
                        offset_for_file = code_fp_to_row_offset.get(filepath)
                        if isinstance(offset_for_file, int):
                            offset = offset_for_file
                original_vector_value: Optional[Any] = error_output.get(vector)
                if original_vector_value:
                    error_output[vector] = str(max(int(original_vector_value) - offset, start))
    except ValueError as e:
        demisto.debug(f'Failed adjusting "{vector}" on validation result {error_output}'
                      f'\n{e}')


def run_validate(path_to_validate: str, json_output_file: str) -> None:
    os.environ['DEMISTO_SDK_SKIP_VERSION_CHECK'] = '1'
    tests_dir = 'Tests'
    if not os.path.exists(tests_dir):
        os.makedirs(tests_dir)
    with open(f'{tests_dir}/id_set.json', 'w') as f:
        json.dump({}, f)
    # old_validate_manager = OldValidateManager(
    #     is_backward_check=False, prev_ver="origin/master", use_git=False, only_committed_files=False,
    #     print_ignored_files=True, skip_conf_json=True, validate_id_set=False, file_path=str(file_path),
    #     validate_all=False, is_external_repo=False, skip_pack_rn_validation=False, print_ignored_errors=True,
    #     silence_init_prints=False, no_docker_checks=False, skip_dependencies=False, id_set_path=None,
    #     staged=False, json_file_path=json_output_file, skip_schema_check=True, create_id_set=False, check_is_unskipped=False)
    # old_validate_manager.run_validation()

    result_writer = CustomResultsWriter(json_file_path=json_output_file)
    config_reader = ConfigReader(category="xsoar_best_practices_path_based_validations")
    initializer = CustomInitializer(
        staged=False,
        committed_only=False,
        file_path=str(path_to_validate),
        execution_mode=ExecutionMode.SPECIFIC_FILES
    )
    new_validate_manager = CustomValidateManger(result_writer, config_reader, initializer, allow_autofix=False)
    exit_code = new_validate_manager.run_validations()
    demisto.info(f'run_validate {exit_code=}')

def run_lint(file_path: str, json_output_file: str) -> None:
    lint_log_dir = os.path.dirname(json_output_file)
    lint_manager = LintManager(
        input=str(file_path), git=False, all_packs=False,
        prev_ver='origin/master', json_file_path=json_output_file
    )
    lint_manager.run(
        parallel=1, no_flake8=False, no_xsoar_linter=False, no_bandit=False, no_mypy=False,
        no_pylint=True, no_coverage=True, coverage_report='', no_vulture=False, no_test=True, no_pwsh_analyze=True,
        no_pwsh_test=True, keep_container=False, test_xml='', failure_report=lint_log_dir, docker_timeout=60,
        docker_image_flag=None, docker_image_target=None
    )


def prepare_content_pack_for_validation(filename: str, data: bytes, tmp_directory: str) -> Tuple[str, Dict]:
    # write zip file data to file system
    zip_path = os.path.abspath(os.path.join(tmp_directory, filename))
    with open(zip_path, 'wb') as fp:
        fp.write(data)

    pack_name = get_pack_name(zip_path)
    contrib_converter = ContributionConverter(name=pack_name, contribution=zip_path, base_dir=tmp_directory)
    code_fp_to_row_offset = convert_contribution_to_pack(contrib_converter)
    # Call the standalone function and get the raw response
    os.remove(zip_path)
    return contrib_converter.pack_dir_path, code_fp_to_row_offset


def prepare_single_content_item_for_validation(filename: str, data: bytes, tmp_directory: str) -> Tuple[str, Dict]:
    content = Content(tmp_directory)
    pack_name = 'TmpPack'
    pack_dir = content.path / 'Packs' / pack_name
    # create pack_metadata.json file in TmpPack
    contrib_converter = ContributionConverter(name=pack_name, base_dir=tmp_directory, pack_dir_name=pack_name,
                                              contribution=pack_name)
    contrib_converter.create_metadata_file({'description': 'Temporary Pack', 'author': 'xsoar'})

    demisto.debug(f'prepare_single_content_item_for_validation: {filename=}')
    prefix = '-'.join(filename.split('-')[:-1])
    demisto.debug(f'prepare_single_content_item_for_validation: {pack_dir=}, {prefix=}')
    containing_dir = pack_dir / ENTITY_TYPE_TO_DIR.get(prefix, 'Integrations')
    containing_dir.mkdir(exist_ok=True)
    demisto.debug(f'prepare_single_content_item_for_validation: {containing_dir=}')
    is_json = filename.casefold().endswith('.json')
    data_as_string = data.decode()
    loaded_data = json.loads(data_as_string) if is_json else yaml.load(data_as_string)
    if is_json:
        data_as_string = json.dumps(loaded_data)
    else:
        buff = io.StringIO()
        yaml.dump(loaded_data, buff)
        data_as_string = buff.getvalue()

    # write content item file to file system
    file_path = containing_dir / filename
    file_path.write_text(data_as_string)
    demisto.debug(f'prepare_single_content_item_for_validation {file_path=}')
    file_type = find_type(str(file_path))
    file_type = file_type.value if file_type else file_type
    demisto.debug(f'prepare_single_content_item_for_validation {file_type=}')

    if is_json or file_type in (FileType.PLAYBOOK.value, FileType.TEST_PLAYBOOK.value):
        return str(file_path), {}

    extractor = YmlSplitter(
        input=str(file_path), file_type=file_type, output=containing_dir,
        no_logging=True, no_pipenv=True, no_basic_fmt=True
    )
    demisto.debug(f'prepare_single_content_item_for_validation 1: {os.listdir()=}')

    # validate the resulting package files, ergo set path_to_validate to the package directory that results
    # from extracting the unified yaml to a package format
    extractor.extract_to_package_format()
    demisto.debug(f'prepare_single_content_item_for_validation 2: {os.listdir()=}')

    for root, dirs, files in os.walk('.'):
        # Print the current root directory
        demisto.debug(f"Root Directory: {root}")

        # Print all directories under the current root
        for dir_name in dirs:
            demisto.debug(f"Directory: {os.path.join(root, dir_name)}")

        # Print all files under the current root
        for file_name in files:
            demisto.debug(f"File: {os.path.join(root, file_name)}")

    code_fp_to_row_offset = {get_extracted_code_filepath(extractor): extractor.lines_inserted_at_code_start}
    demisto.debug(f'prepare_single_content_item_for_validation 4: {code_fp_to_row_offset=}')
    return extractor.get_output_path(), code_fp_to_row_offset


def validate_content(filename: str, data: bytes, tmp_directory: str) -> List:
    json_output_path = os.path.join(tmp_directory, 'validation_res.json')
    lint_output_path = os.path.join(tmp_directory, 'lint_res.json')
    output_capture = io.StringIO()
    demisto.debug(f'validate_content {tmp_directory=} | {filename=} ')
    with redirect_stderr(output_capture):
        with TemporaryFile(mode='w+') as tmp:
            logging_setup(
                calling_function='validate_content',
                path=tmp.name,
                initial=True
            )
            logger.enable(None)

            if filename.endswith('.zip'):
                path_to_validate, code_fp_to_row_offset = prepare_content_pack_for_validation(
                    filename, data, tmp_directory
                )
            else:
                path_to_validate, code_fp_to_row_offset = prepare_single_content_item_for_validation(
                    filename, data, tmp_directory
                )
            run_validate(path_to_validate, json_output_path)
            # run_lint(path_to_validate, lint_output_path)

            demisto.debug("log capture:" + tmp.read())

            all_outputs = []
            with open(json_output_path, 'r') as json_outputs:
                outputs_as_json = json.load(json_outputs)
                demisto.debug(f'2 {outputs_as_json=}')
                if outputs_as_json:
                    if type(outputs_as_json) == list:
                        all_outputs.extend(outputs_as_json)
                    else:
                        all_outputs.append(outputs_as_json)

            # with open(lint_output_path, 'r') as json_outputs:
            #     outputs_as_json = json.load(json_outputs)
            #     if outputs_as_json:
            #         if type(outputs_as_json) == list:
            #             for validation in outputs_as_json:
            #                 adjust_linter_row_and_col(validation, code_fp_to_row_offset)
            #             all_outputs.extend(outputs_as_json)
            #         else:
            #             all_outputs.append(outputs_as_json)
    return all_outputs


def get_content_modules(content_tmp_dir: str, verify_ssl: bool = True) -> None:
    """Copies the required content modules for linting from the cached dir
    The cached dir is updated once a day

    Args:
         content_tmp_dir (str): The content tmp dir to copy the content modules to
         verify_ssl (bool): Whether to verify SSL
    """
    modules = [
        {
            'file': 'CommonServerPython.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
                          '/CommonServerPython/CommonServerPython.py',
            'content_path': 'Packs/Base/Scripts/CommonServerPython',
        },
        {
            'file': 'CommonServerPowerShell.ps1',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
                          '/CommonServerPowerShell/CommonServerPowerShell.ps1',
            'content_path': 'Packs/Base/Scripts/CommonServerPowerShell',
        },
        {
            'file': 'demistomock.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py',
            'content_path': 'Tests/demistomock',
        },
        {
            'file': 'demistomock.ps1',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1',
            'content_path': 'Tests/demistomock',
        },
        {
            'file': 'tox.ini',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/tox.ini',
            'content_path': '.'
        },
        {
            'file': 'conftest.py',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest'
                          '/conftest.py',
            'content_path': 'Tests/scripts/dev_envs/pytest'
        },
        {
            'file': 'approved_usecases.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Config/approved_usecases.json',
            'content_path': 'Config',
        },
        {
            'file': 'approved_tags.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Config/approved_tags.json',
            'content_path': 'Config',
        },
        {
            'file': 'approved_categories.json',
            'github_url': 'https://raw.githubusercontent.com/demisto/content/master/'
                          'Config/approved_categories.json',
            'content_path': 'Config',
        },

    ]
    for module in modules:
        content_path = os.path.join(content_tmp_dir, module['content_path'])
        os.makedirs(content_path, exist_ok=True)
        try:
            cached_module_path = os.path.join(CACHED_MODULES_DIR, module['file'])
            fname = Path(cached_module_path)
            modified_time = datetime.fromtimestamp(fname.stat().st_mtime) if os.path.isfile(cached_module_path) \
                else datetime(1970, 1, 1)
            if modified_time + timedelta(days=1) < datetime.utcnow():
                demisto.debug(f'Downloading {module["file"]} from git')
                res = requests.get(module['github_url'], verify=verify_ssl, timeout=10)
                res.raise_for_status()
                with open(cached_module_path, 'wb') as f:
                    f.write(res.content)
            demisto.debug(f'Copying from {cached_module_path} to {content_path}')
            copy(cached_module_path, content_path)
        except Exception as e:
            fallback_path = f'/home/demisto/{module["file"]}'
            demisto.debug(f'Failed downloading content module {module["github_url"]} - {e}. '
                          f'Copying from {fallback_path}')
            copy(fallback_path, content_path)


def get_file_name_and_contents(
    filename: Optional[str] = None,
    data: Optional[str] = None,
    entry_id: Optional[str] = None,
):
    if filename and data:
        return filename, b64decode(data)
    elif entry_id:
        file_object = demisto.getFilePath(entry_id)

        with open(file_object['path'], 'rb') as f:
            file_contents = f.read()
        return file_object['name'], file_contents


def main():
    cwd = os.getcwd()
    content_tmp_dir = TemporaryDirectory()
    try:
        args = demisto.args()
        if args.get('use_system_proxy') == 'no':
            del os.environ['HTTP_PROXY']
            del os.environ['HTTPS_PROXY']
            del os.environ['http_proxy']
            del os.environ['https_proxy']
        verify_ssl = argToBoolean(args.get('trust_any_certificate'))

        content_repo = git.Repo.init(content_tmp_dir.name)
        content_repo.create_remote('origin', 'https://github.com/demisto/content.git')
        os.makedirs(CACHED_MODULES_DIR, exist_ok=True)

        get_content_modules(content_tmp_dir.name, verify_ssl)

        filename, file_contents = get_file_name_and_contents(
            args.get('filename'),
            args.get('data'),
            args.get('entry_id'),
        )
        os.makedirs(content_tmp_dir.name, exist_ok=True)
        os.chdir(content_tmp_dir.name)

        result = validate_content(filename, file_contents, content_tmp_dir.name)
        outputs = []
        for validation in result:
            demisto.debug(f'main validation tested: {json.dumps(validation, indent=4)}')
            if validation.get('ui') or validation.get('fileType') in {'py', 'ps1', 'yml'}:
                outputs.append({
                    'Name': validation.get('name'),
                    'Error': validation.get('message'),
                    'Line': validation.get('row'),
                })
                demisto.debug(f'main validation output added: {json.dumps(outputs[-1], indent=4)}')

        demisto.debug(f'main {outputs=}')
        return_results(CommandResults(
            readable_output=tableToMarkdown('Validation Results', outputs, headers=['Name', 'Error', 'Line']),
            outputs_prefix='ValidationResult',
            outputs=outputs,
            raw_response=result,
        ))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute ValidateContent. Error: {str(e)}')
    finally:
        content_tmp_dir.cleanup()
        os.chdir(cwd)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
