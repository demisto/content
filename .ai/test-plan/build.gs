/**
 * Test Plan – workbook builder.
 *
 * Run `buildWorkbook()` from the Apps Script editor (or the "🧪 Test Plan" menu)
 * to generate the entire formatted workbook from the constants defined in
 * `data.gs` (CONFIG_LISTS, JIRA_BASE_URL, SETUPS, TEST_CASES).
 *
 * The builder is idempotent: generated sheets are recreated on every run,
 * except `▶️ Runs` and `🐞 Bugs`, whose user-entered data is preserved.
 */

/* eslint-disable no-unused-vars */

/** Canonical sheet names. Every formula is built from these constants. */
const SHEETS = {
  README: '📖 README',
  CONFIG: '⚙️ Config',
  SETUP: '🧱 Setup',
  TESTS: '🧪 TestCases',
  RUNS: '▶️ Runs',
  BUGS: '🐞 Bugs',
  DASHBOARD: '📊 Dashboard',
  COVERAGE: '🎯 Coverage',
  V_MARKETPLACE: '👁️ Marketplace',
  V_MANAGED: '👁️ Managed',
  V_CONNECTUS: '👁️ Connectus',
  V_CI: '👁️ CI'
};

/** Desired left-to-right tab order. */
const SHEET_ORDER = [
  SHEETS.README,
  SHEETS.CONFIG,
  SHEETS.SETUP,
  SHEETS.TESTS,
  SHEETS.RUNS,
  SHEETS.BUGS,
  SHEETS.DASHBOARD,
  SHEETS.COVERAGE,
  SHEETS.V_MARKETPLACE,
  SHEETS.V_MANAGED,
  SHEETS.V_CONNECTUS,
  SHEETS.V_CI
];

/** Shared palette. */
const COLORS = {
  slate: '#546E7A',
  slateDark: '#37474F',
  slateLight: '#78909C',
  blue: '#1565C0',
  blueLight: '#42A5F5',
  purple: '#6A1B9A',
  purpleLight: '#AB47BC',
  green: '#2E7D32',
  greenLight: '#66BB6A',
  teal: '#00695C',
  red: '#B71C1C',
  setupHeader: '#455A64',
  passBg: '#E8F5E9',
  failBg: '#FFEBEE',
  failText: '#B71C1C',
  blockedBg: '#FFF3E0',
  mutedText: '#9E9E9E',
  deprecatedBg: '#EEEEEE',
  white: '#FFFFFF'
};

/** ID prefixes offered by `addTestRow()`. */
const ID_PREFIXES = ['DP', 'CMN', 'RN', 'NC', 'CSP'];

/** First data row of the TestCases sheet (two header rows above it). */
const TC_FIRST_ROW = 3;
/** Last row that receives validation / conditional formatting on TestCases. */
const TC_LAST_ROW = 500;

/* ------------------------------------------------------------------ */
/* Generic helpers                                                     */
/* ------------------------------------------------------------------ */

/**
 * Quote a sheet name for use inside an A1 formula.
 * @param {string} name Sheet name (may contain emoji / spaces).
 * @return {string} e.g. `'🧪 TestCases'!`
 */
function ref_(name) {
  return "'" + String(name).replace(/'/g, "''") + "'!";
}

/**
 * Fetch a sheet by name, creating it when missing.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} name Sheet name.
 * @return {Sheet} The existing or newly created sheet.
 */
function getOrCreateSheet_(ss, name) {
  return ss.getSheetByName(name) || ss.insertSheet(name);
}

/**
 * Return an empty sheet with the given name.
 *
 * The sheet is wiped in place rather than deleted and recreated: deleting a
 * sheet turns every cross-sheet reference pointing at it into a permanent
 * `#REF!`, which would break the workbook on the second run.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} name Sheet name.
 * @return {Sheet} A blank sheet.
 */
function resetSheet_(ss, name) {
  const sheet = getOrCreateSheet_(ss, name);
  sheet.clear();
  sheet.clearConditionalFormatRules();
  sheet.clearNotes();

  try {
    const filter = sheet.getFilter();
    if (filter) {
      filter.remove();
    }
  } catch (e) {
    // No filter present.
  }

  try {
    const bandings = sheet.getBandings();
    for (let i = 0; i < bandings.length; i++) {
      bandings[i].remove();
    }
  } catch (e) {
    // No banding present.
  }

  // Unmerge everything so re-runs never hit "already merged" errors.
  try {
    sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns()).breakApart();
  } catch (e) {
    // Nothing merged.
  }

  sheet.setFrozenRows(0);
  sheet.setFrozenColumns(0);
  return sheet;
}

/**
 * Grow a sheet so it has at least the requested number of rows and columns.
 * @param {Sheet} sheet Target sheet.
 * @param {number} rows Minimum row count.
 * @param {number} cols Minimum column count.
 */
function ensureSize_(sheet, rows, cols) {
  const maxRows = sheet.getMaxRows();
  if (rows > maxRows) {
    sheet.insertRowsAfter(maxRows, rows - maxRows);
  }
  const maxCols = sheet.getMaxColumns();
  if (cols > maxCols) {
    sheet.insertColumnsAfter(maxCols, cols - maxCols);
  }
}

/**
 * Create every sheet up front so cross-sheet formulas and named-range based
 * validation always resolve, whatever order the builders run in.
 * @param {Spreadsheet} ss The spreadsheet.
 */
function ensureAllSheets_(ss) {
  for (let i = 0; i < SHEET_ORDER.length; i++) {
    getOrCreateSheet_(ss, SHEET_ORDER[i]);
  }
}

/**
 * Convert a 1-based column index to its A1 letter.
 * @param {number} index 1-based column index.
 * @return {string} Column letter(s).
 */
function colLetter_(index) {
  let letter = '';
  let n = index;
  while (n > 0) {
    const rem = (n - 1) % 26;
    letter = String.fromCharCode(65 + rem) + letter;
    n = Math.floor((n - rem) / 26);
  }
  return letter;
}

/**
 * Build a data-validation rule bound to a named range.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} listKey Key of CONFIG_LISTS (named range is `List_<key>`).
 * @return {DataValidation|null} The rule, or null when the range is missing.
 */
function listValidation_(ss, listKey) {
  const range = ss.getRangeByName('List_' + listKey);
  if (!range) {
    return null;
  }
  return SpreadsheetApp.newDataValidation()
    .requireValueInRange(range, true)
    .setAllowInvalid(false)
    .build();
}

/**
 * Build a data-validation rule bound to an arbitrary A1 range on a sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} sheetName Sheet holding the source values.
 * @param {string} a1 A1 notation of the source range.
 * @return {DataValidation|null} The rule, or null when the sheet is missing.
 */
function rangeValidation_(ss, sheetName, a1) {
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    return null;
  }
  return SpreadsheetApp.newDataValidation()
    .requireValueInRange(sheet.getRange(a1), true)
    .setAllowInvalid(false)
    .build();
}

/**
 * Apply a validation rule to a column range, ignoring missing rules.
 * @param {Sheet} sheet Target sheet.
 * @param {number} col 1-based column index.
 * @param {number} firstRow First row to cover.
 * @param {number} lastRow Last row to cover.
 * @param {DataValidation|null} rule Rule to apply.
 */
function applyValidation_(sheet, col, firstRow, lastRow, rule) {
  if (!rule) {
    return;
  }
  sheet.getRange(firstRow, col, lastRow - firstRow + 1, 1).setDataValidation(rule);
}

/**
 * Remove any banding already present on a range, then apply light grey banding.
 * @param {Range} range Target range.
 */
function safeBanding_(range) {
  try {
    const bandings = range.getSheet().getBandings();
    for (let i = 0; i < bandings.length; i++) {
      bandings[i].remove();
    }
  } catch (e) {
    // Ignore – banding removal is best effort.
  }
  try {
    range.applyRowBanding(SpreadsheetApp.BandingTheme.LIGHT_GREY, false, false);
  } catch (e) {
    // A banding may already cover part of the range; not fatal.
  }
}

/**
 * Create a basic filter on a range, removing an existing one first.
 * @param {Sheet} sheet Target sheet.
 * @param {string} a1 A1 notation for the filter range.
 */
function safeFilter_(sheet, a1) {
  try {
    const existing = sheet.getFilter();
    if (existing) {
      existing.remove();
    }
    sheet.getRange(a1).createFilter();
  } catch (e) {
    // Filters are cosmetic – never fail the build because of one.
  }
}

/**
 * Number of non-empty data rows below the header of a sheet.
 * @param {Sheet} sheet Target sheet.
 * @param {number} headerRows Count of header rows.
 * @return {number} Data row count.
 */
function dataRowCount_(sheet, headerRows) {
  const last = sheet.getLastRow();
  return Math.max(0, last - headerRows);
}

/* ------------------------------------------------------------------ */
/* Orchestration                                                       */
/* ------------------------------------------------------------------ */

/**
 * Build (or rebuild) the whole workbook.
 * Safe to re-run: `▶️ Runs` and `🐞 Bugs` keep any data already entered.
 */
function buildWorkbook() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  // Create every tab first so cross-sheet formulas never resolve to #REF!.
  ensureAllSheets_(ss);

  buildConfigSheet_(ss);
  buildSetupSheet_(ss);
  buildTestCasesSheet_(ss);
  buildRunsSheet_(ss);
  buildBugsSheet_(ss);
  buildDashboardSheet_(ss);
  buildCoverageSheet_(ss);
  buildViewSheets_(ss);
  buildReadmeSheet_(ss);

  orderSheets_(ss);
  removeDefaultSheet_(ss);

  SpreadsheetApp.getActive().toast('Workbook rebuilt successfully.', '🧪 Test Plan', 5);
}

/**
 * Re-apply formatting, validation and conditional formatting without touching
 * any data rows. Useful after manual edits.
 */
function applyAllFormatting() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const tests = ss.getSheetByName(SHEETS.TESTS);
  if (tests) {
    formatTestCasesSheet_(ss, tests);
  }
  const setup = ss.getSheetByName(SHEETS.SETUP);
  if (setup) {
    formatSetupSheet_(ss, setup);
  }
  const runs = ss.getSheetByName(SHEETS.RUNS);
  if (runs) {
    formatRunsSheet_(ss, runs);
  }
  const bugs = ss.getSheetByName(SHEETS.BUGS);
  if (bugs) {
    formatBugsSheet_(ss, bugs);
  }

  orderSheets_(ss);
  SpreadsheetApp.getActive().toast('Formatting re-applied.', '🧪 Test Plan', 5);
}

/**
 * Move every known sheet into SHEET_ORDER position.
 * @param {Spreadsheet} ss The spreadsheet.
 */
function orderSheets_(ss) {
  for (let i = 0; i < SHEET_ORDER.length; i++) {
    const sheet = ss.getSheetByName(SHEET_ORDER[i]);
    if (sheet) {
      ss.setActiveSheet(sheet);
      ss.moveActiveSheet(i + 1);
    }
  }
  const first = ss.getSheetByName(SHEETS.README);
  if (first) {
    ss.setActiveSheet(first);
  }
}

/** Names Google gives a brand-new, untouched first tab. */
const DEFAULT_SHEET_NAMES = ['Sheet1', 'Sheet 1', 'Blad1', 'Hoja 1', 'Feuille 1', 'Tabellenblatt1'];

/**
 * Delete the default "Sheet1" tab when it is still empty. Any other user sheet
 * is left untouched.
 * @param {Spreadsheet} ss The spreadsheet.
 */
function removeDefaultSheet_(ss) {
  const sheets = ss.getSheets();
  for (let i = 0; i < sheets.length; i++) {
    const name = sheets[i].getName();
    const isDefault = DEFAULT_SHEET_NAMES.indexOf(name) !== -1;
    if (isDefault && sheets[i].getLastRow() === 0 && ss.getSheets().length > 1) {
      ss.deleteSheet(sheets[i]);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Custom menu                                                         */
/* ------------------------------------------------------------------ */

/** Install the custom "🧪 Test Plan" menu when the spreadsheet is opened. */
function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('🧪 Test Plan')
    .addItem('➕ Add Test Row', 'addTestRow')
    .addItem('🔄 Start New Run', 'startNewRun')
    .addSeparator()
    .addItem('🏗️ Rebuild Workbook', 'buildWorkbook')
    .addItem('🎨 Reapply Formatting', 'applyAllFormatting')
    .addToUi();
}

/* ------------------------------------------------------------------ */
/* ⚙️ Config                                                           */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the Config sheet: one column per CONFIG_LISTS key plus a named range
 * `List_<Key>` covering rows 2..200 so new values are picked up automatically.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Config sheet.
 */
function buildConfigSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.CONFIG);
  const keys = Object.keys(CONFIG_LISTS);
  ensureSize_(sheet, 200, keys.length);

  // Header row.
  sheet.getRange(1, 1, 1, keys.length).setValues([keys]);

  // Values, written column by column in a single batch per column.
  let maxLen = 0;
  for (let c = 0; c < keys.length; c++) {
    const values = CONFIG_LISTS[keys[c]];
    maxLen = Math.max(maxLen, values.length);
    const matrix = values.map(function (v) {
      return [v];
    });
    if (matrix.length) {
      sheet.getRange(2, c + 1, matrix.length, 1).setValues(matrix);
    }
  }

  sheet.getRange(1, 1, 1, keys.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.slateDark)
    .setHorizontalAlignment('center');

  sheet.setFrozenRows(1);
  for (let c = 1; c <= keys.length; c++) {
    sheet.setColumnWidth(c, 150);
  }

  createConfigNamedRanges_(ss, sheet, keys);
  return sheet;
}

/**
 * (Re)create one named range per Config column.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Config sheet.
 * @param {!Array<string>} keys CONFIG_LISTS keys in column order.
 */
function createConfigNamedRanges_(ss, sheet, keys) {
  const wanted = {};
  for (let i = 0; i < keys.length; i++) {
    wanted['List_' + keys[i]] = true;
  }

  const existing = ss.getNamedRanges();
  for (let i = 0; i < existing.length; i++) {
    if (wanted[existing[i].getName()]) {
      existing[i].remove();
    }
  }

  for (let c = 0; c < keys.length; c++) {
    const letter = colLetter_(c + 1);
    const range = sheet.getRange(letter + '2:' + letter + '200');
    ss.setNamedRange('List_' + keys[c], range);
  }
}

/* ------------------------------------------------------------------ */
/* 🧱 Setup                                                            */
/* ------------------------------------------------------------------ */

/** Setup sheet headers (8 data columns + 2 formula columns). */
const SETUP_HEADERS = [
  'Setup ID',
  'Title',
  'Type',
  'Description',
  'Deployment Config',
  'Depends On',
  'Build/Bucket',
  'Status',
  '# Tests',
  'Blocked Tests'
];

/**
 * Rebuild the Setup sheet from SETUPS and add live count formulas.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Setup sheet.
 */
function buildSetupSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.SETUP);
  ensureSize_(sheet, 100, SETUP_HEADERS.length);

  sheet.getRange(1, 1, 1, SETUP_HEADERS.length).setValues([SETUP_HEADERS]);
  if (SETUPS.length) {
    sheet.getRange(2, 1, SETUPS.length, 8).setValues(SETUPS);

    const tc = ref_(SHEETS.TESTS);
    const formulas = SETUPS.map(function (row, i) {
      const r = i + 2;
      return [
        '=COUNTIF(' + tc + '$Q$3:$Q,$A' + r + ')',
        '=COUNTIFS(' + tc + '$Q$3:$Q,$A' + r + ',' + tc + '$X$3:$X,"Blocked")'
      ];
    });
    sheet.getRange(2, 9, formulas.length, 2).setFormulas(formulas);
  }

  formatSetupSheet_(ss, sheet);
  return sheet;
}

/**
 * Apply formatting, validation and conditional formatting to the Setup sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Setup sheet.
 */
function formatSetupSheet_(ss, sheet) {
  const lastRow = 100;

  sheet.getRange(1, 1, 1, SETUP_HEADERS.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.setupHeader)
    .setHorizontalAlignment('center')
    .setWrap(true);

  sheet.setFrozenRows(1);
  const widths = [110, 300, 110, 420, 260, 120, 160, 120, 90, 120];
  for (let c = 0; c < widths.length; c++) {
    sheet.setColumnWidth(c + 1, widths[c]);
  }
  sheet.getRange(2, 4, lastRow - 1, 1).setWrap(true);
  sheet.getRange(2, 5, lastRow - 1, 1).setWrap(true);

  applyValidation_(sheet, 3, 2, lastRow, listValidation_(ss, 'SetupType'));
  applyValidation_(sheet, 8, 2, lastRow, listValidation_(ss, 'SetupStatus'));

  const target = sheet.getRange(2, 1, lastRow - 1, SETUP_HEADERS.length);
  const rules = [
    statusRule_(target, '=$H2="Done"', '#E8F5E9', COLORS.green, true),
    statusRule_(target, '=$H2="Failed"', COLORS.failBg, COLORS.failText, true),
    statusRule_(target, '=$H2="In Progress"', COLORS.blockedBg, null, false),
    statusRule_(target, '=$H2="Pending"', null, COLORS.mutedText, false)
  ];
  sheet.setConditionalFormatRules(rules);
}

/**
 * Build a conditional-format rule from a custom formula.
 * @param {Range} range Range the rule applies to.
 * @param {string} formula Custom formula.
 * @param {?string} background Background color or null.
 * @param {?string} fontColor Font color or null.
 * @param {boolean} bold Whether to bold the text.
 * @return {ConditionalFormatRule} The built rule.
 */
function statusRule_(range, formula, background, fontColor, bold) {
  let builder = SpreadsheetApp.newConditionalFormatRule().whenFormulaSatisfied(formula);
  if (background) {
    builder = builder.setBackground(background);
  }
  if (fontColor) {
    builder = builder.setFontColor(fontColor);
  }
  if (bold) {
    builder = builder.setBold(true);
  }
  return builder.setRanges([range]).build();
}

/* ------------------------------------------------------------------ */
/* 🧪 TestCases                                                        */
/* ------------------------------------------------------------------ */

/** Column headers of the TestCases sheet (A..Z, 26 columns). */
const TC_HEADERS = [
  'ID', 'Ticket', 'Jira', 'Title', 'Active', 'Feature',
  'Tenant', 'Tenant Scope', 'Phase', 'Pack State', 'Pack Type', 'Coupling',
  'Test Type', 'Priority', 'Suite', 'Automatable',
  'Setup Ref', 'Preconditions', 'Steps', 'Expected Result', 'Verification',
  'Test Data / Packs', 'Owner',
  'Latest Status', 'Latest Run', 'Open Bug'
];

/** Merged banner blocks of row 1: [label, firstCol, lastCol, color]. */
const TC_BLOCKS = [
  ['Identity', 1, 6, COLORS.slate],
  ['Classification', 7, 16, COLORS.blue],
  ['Execution', 17, 23, COLORS.purple],
  ['Status (auto)', 24, 26, COLORS.green]
];

/** Lighter tint used for the row-2 header of each block. */
const TC_BLOCK_TINTS = [COLORS.slateLight, COLORS.blueLight, COLORS.purpleLight, COLORS.greenLight];

/**
 * Number of frozen columns on the TestCases sheet.
 *
 * Used both when splitting the row-1 banner merges and when calling
 * `setFrozenColumns()`, so the two can never drift apart: Google Sheets
 * refuses to freeze a column boundary that cuts a merged range in half.
 */
const TC_FROZEN_COLS = 2;

/** Font size of the row-1 banner segments (identical for every segment). */
const TC_BANNER_FONT_SIZE = 11;

/**
 * Merge one row-1 banner, splitting it at the frozen-column boundary.
 *
 * A merged range may not straddle the freeze line, so a block that contains
 * the boundary is written as two adjacent merges sharing identical styling —
 * visually still one continuous bar. The label goes into the wider segment
 * (ties go to the right-hand one) and the other segment is left empty, which
 * avoids a truncated or duplicated label.
 * @param {Sheet} sheet Target sheet.
 * @param {number} startCol First column of the banner (1-based).
 * @param {number} endCol Last column of the banner (1-based, inclusive).
 * @param {string} label Banner text.
 * @param {string} bgColor Banner background color.
 * @param {number} frozenCols Number of columns that will be frozen.
 */
function mergeBannerSegments_(sheet, startCol, endCol, label, bgColor, frozenCols) {
  const segments = [];
  if (frozenCols >= startCol && frozenCols < endCol) {
    segments.push([startCol, frozenCols]);
    segments.push([frozenCols + 1, endCol]);
  } else {
    segments.push([startCol, endCol]);
  }

  // Widest segment carries the label; on a tie the right-hand one wins.
  let labelIndex = 0;
  for (let i = 1; i < segments.length; i++) {
    const width = segments[i][1] - segments[i][0] + 1;
    const widest = segments[labelIndex][1] - segments[labelIndex][0] + 1;
    if (width >= widest) {
      labelIndex = i;
    }
  }

  for (let i = 0; i < segments.length; i++) {
    const range = sheet.getRange(1, segments[i][0], 1, segments[i][1] - segments[i][0] + 1);
    range.merge();
    range.setValue(i === labelIndex ? label : '');
    range.setBackground(bgColor)
      .setFontColor(COLORS.white)
      .setFontWeight('bold')
      .setFontSize(TC_BANNER_FONT_SIZE)
      .setHorizontalAlignment('center')
      .setVerticalAlignment('middle');
  }
}

/**
 * (Re)build the four row-1 banners of the TestCases sheet.
 *
 * Row 1 is unmerged first, so this is safe to run again on a sheet that was
 * already built - including one built by an older version that merged across
 * the freeze line.
 * @param {Sheet} sheet The TestCases sheet.
 */
function applyTestCaseBanners_(sheet) {
  try {
    sheet.getRange(1, 1, 1, sheet.getMaxColumns()).breakApart();
  } catch (e) {
    // Nothing merged in row 1.
  }

  for (let b = 0; b < TC_BLOCKS.length; b++) {
    const block = TC_BLOCKS[b];
    mergeBannerSegments_(sheet, block[1], block[2], block[0], block[3], TC_FROZEN_COLS);
  }
}

/** Map of 1-based TestCases column -> CONFIG_LISTS key used for validation. */
const TC_VALIDATION = {
  2: 'Ticket',
  5: 'Active',
  6: 'Feature',
  7: 'Tenant',
  9: 'Phase',
  10: 'PackState',
  11: 'PackType',
  12: 'Coupling',
  13: 'TestType',
  14: 'Priority',
  15: 'Suite',
  16: 'Automatable',
  21: 'VerificationMethod'
};

/**
 * Convert one TEST_CASES row (21 source columns) into the 26-column layout.
 * Jira (C), Latest Status (X), Latest Run (Y) and Open Bug (Z) are written
 * separately as formulas; Owner (W) is intentionally left blank.
 * @param {!Array<*>} src A row from TEST_CASES.
 * @return {!Array<*>} A 26-cell row.
 */
function testCaseRowToSheetRow_(src) {
  return [
    src[0],  // A ID
    src[1],  // B Ticket
    '',      // C Jira (formula)
    src[2],  // D Title
    src[3],  // E Active
    src[4],  // F Feature
    src[5],  // G Tenant
    src[6],  // H Tenant Scope
    src[7],  // I Phase
    src[8],  // J Pack State
    src[9],  // K Pack Type
    src[10], // L Coupling
    src[11], // M Test Type
    src[12], // N Priority
    src[13], // O Suite
    src[20], // P Automatable
    src[14], // Q Setup Ref
    src[15], // R Preconditions
    src[16], // S Steps
    src[17], // T Expected Result
    src[18], // U Verification
    src[19], // V Test Data / Packs
    '',      // W Owner
    '',      // X Latest Status (formula)
    '',      // Y Latest Run (formula)
    ''       // Z Open Bug (formula)
  ];
}

/**
 * Rebuild the TestCases sheet: banners, headers, data rows and formulas.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The TestCases sheet.
 */
function buildTestCasesSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.TESTS);
  ensureSize_(sheet, TC_LAST_ROW, TC_HEADERS.length);

  // Row 1 - merged block banners, split at the frozen-column boundary.
  applyTestCaseBanners_(sheet);

  // Row 2 - real column headers.
  sheet.getRange(2, 1, 1, TC_HEADERS.length).setValues([TC_HEADERS]);

  // Data rows.
  const rows = TEST_CASES.map(testCaseRowToSheetRow_);
  if (rows.length) {
    sheet.getRange(TC_FIRST_ROW, 1, rows.length, TC_HEADERS.length).setValues(rows);
    writeTestCaseFormulas_(sheet, rows.length);
  }

  formatTestCasesSheet_(ss, sheet);
  return sheet;
}

/**
 * Write the Jira / Latest Status / Latest Run / Open Bug formulas.
 * @param {Sheet} sheet The TestCases sheet.
 * @param {number} rowCount Number of data rows.
 */
function writeTestCaseFormulas_(sheet, rowCount) {
  const jira = [];
  const status = [];
  for (let i = 0; i < rowCount; i++) {
    const r = TC_FIRST_ROW + i;
    jira.push([jiraFormula_('$B' + r)]);
    status.push([
      latestRunFormula_('G', r, '"Not Run"'),
      latestRunFormula_('A', r, '""'),
      openBugFormula_(r)
    ]);
  }
  sheet.getRange(TC_FIRST_ROW, 3, rowCount, 1).setFormulas(jira);
  sheet.getRange(TC_FIRST_ROW, 24, rowCount, 3).setFormulas(status);
}

/**
 * HYPERLINK formula for a Jira key cell.
 * @param {string} cell A1 reference holding the Jira key.
 * @return {string} The formula.
 */
function jiraFormula_(cell) {
  return '=IF(' + cell + '="","",HYPERLINK("' + JIRA_BASE_URL + '"&' + cell + ',' + cell + '))';
}

/**
 * Value of `column` on the most recent Runs row matching this test ID.
 * @param {string} column Column letter on the Runs sheet.
 * @param {number} row Row on the TestCases sheet.
 * @param {string} fallback Literal returned when there is no matching run.
 * @return {string} The formula.
 */
function latestRunFormula_(column, row, fallback) {
  const runs = ref_(SHEETS.RUNS);
  return '=IFERROR(INDEX(FILTER(' + runs + '$' + column + '$2:$' + column + ',' +
    runs + '$B$2:$B=$A' + row + '),COUNTIF(' + runs + '$B$2:$B,$A' + row + ')),' + fallback + ')';
}

/**
 * Comma-joined list of not-yet-closed bug IDs for this test.
 * @param {number} row Row on the TestCases sheet.
 * @return {string} The formula.
 */
function openBugFormula_(row) {
  const bugs = ref_(SHEETS.BUGS);
  return '=IFERROR(TEXTJOIN(", ",TRUE,FILTER(' + bugs + '$A$2:$A,' + bugs + '$C$2:$C=$A' + row + ',' +
    bugs + '$F$2:$F<>"Fixed",' + bugs + '$F$2:$F<>"Verified")),"")';
}

/**
 * Apply header styling, widths, validation, banding, conditional formatting,
 * protection and the basic filter to the TestCases sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The TestCases sheet.
 */
function formatTestCasesSheet_(ss, sheet) {
  // Rebuild the banners before freezing: the merges must already be split at
  // the freeze boundary, otherwise setFrozenColumns() throws. Doing it here
  // also repairs sheets that still carry an old straddling merge.
  applyTestCaseBanners_(sheet);

  for (let b = 0; b < TC_BLOCKS.length; b++) {
    const block = TC_BLOCKS[b];
    sheet.getRange(2, block[1], 1, block[2] - block[1] + 1)
      .setBackground(TC_BLOCK_TINTS[b])
      .setFontColor(COLORS.white)
      .setFontWeight('bold')
      .setWrap(true)
      .setHorizontalAlignment('center')
      .setVerticalAlignment('middle');
  }
  sheet.setRowHeight(1, 26);
  sheet.setRowHeight(2, 40);
  sheet.setFrozenRows(2);
  sheet.setFrozenColumns(TC_FROZEN_COLS);

  applyTestCaseWidths_(sheet);
  applyTestCaseValidation_(ss, sheet);

  const dataRows = Math.max(1, sheet.getLastRow() - 2);
  sheet.setRowHeights(TC_FIRST_ROW, dataRows, 22);

  // Long-text columns are clipped so rows stay compact.
  const clip = [18, 19, 20];
  for (let i = 0; i < clip.length; i++) {
    sheet.getRange(TC_FIRST_ROW, clip[i], TC_LAST_ROW - TC_FIRST_ROW + 1, 1)
      .setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP)
      .setVerticalAlignment('middle');
  }

  safeBanding_(sheet.getRange(TC_FIRST_ROW, 1, dataRows, TC_HEADERS.length));
  applyTestCaseConditionalFormats_(sheet);
  protectStatusColumns_(sheet);
  safeFilter_(sheet, 'A2:Z');
}

/**
 * Set sensible column widths on the TestCases sheet.
 * @param {Sheet} sheet The TestCases sheet.
 */
function applyTestCaseWidths_(sheet) {
  const widths = [
    90,  // A ID
    110, // B Ticket
    110, // C Jira
    300, // D Title
    120, // E Active
    150, // F Feature
    120, // G Tenant
    160, // H Tenant Scope
    140, // I Phase
    150, // J Pack State
    130, // K Pack Type
    120, // L Coupling
    120, // M Test Type
    120, // N Priority
    120, // O Suite
    120, // P Automatable
    120, // Q Setup Ref
    220, // R Preconditions
    320, // S Steps
    360, // T Expected Result
    130, // U Verification
    180, // V Test Data / Packs
    130, // W Owner
    130, // X Latest Status
    120, // Y Latest Run
    140  // Z Open Bug
  ];
  for (let c = 0; c < widths.length; c++) {
    sheet.setColumnWidth(c + 1, widths[c]);
  }
}

/**
 * Attach dropdown validation to every enum column of the TestCases sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The TestCases sheet.
 */
function applyTestCaseValidation_(ss, sheet) {
  Object.keys(TC_VALIDATION).forEach(function (col) {
    applyValidation_(sheet, Number(col), TC_FIRST_ROW, TC_LAST_ROW, listValidation_(ss, TC_VALIDATION[col]));
  });
  applyValidation_(sheet, 17, TC_FIRST_ROW, TC_LAST_ROW, rangeValidation_(ss, SHEETS.SETUP, '$A$2:$A$100'));
}

/**
 * Conditional formatting driven by Latest Status, Active and Priority.
 * @param {Sheet} sheet The TestCases sheet.
 */
function applyTestCaseConditionalFormats_(sheet) {
  const all = sheet.getRange('A3:Z' + TC_LAST_ROW);
  const priority = sheet.getRange('N3:N' + TC_LAST_ROW);

  const deprecated = SpreadsheetApp.newConditionalFormatRule()
    .whenFormulaSatisfied('=$E3="Deprecated"')
    .setBackground(COLORS.deprecatedBg)
    .setFontColor(COLORS.mutedText)
    .setItalic(true)
    .setStrikethrough(true)
    .setRanges([all])
    .build();

  sheet.setConditionalFormatRules([
    deprecated,
    statusRule_(all, '=$X3="Pass"', COLORS.passBg, null, false),
    statusRule_(all, '=$X3="Fail"', COLORS.failBg, COLORS.failText, true),
    statusRule_(all, '=$X3="Blocked"', COLORS.blockedBg, null, false),
    statusRule_(all, '=$X3="Skipped"', null, COLORS.mutedText, false),
    statusRule_(all, '=$X3="N-A"', null, COLORS.mutedText, false),
    statusRule_(priority, '=$N3="P0"', null, COLORS.failText, true)
  ]);
}

/**
 * Warn users before they overwrite the auto-computed status columns X:Z.
 * @param {Sheet} sheet The TestCases sheet.
 */
function protectStatusColumns_(sheet) {
  try {
    const existing = sheet.getProtections(SpreadsheetApp.ProtectionType.RANGE);
    for (let i = 0; i < existing.length; i++) {
      existing[i].remove();
    }
    sheet.getRange('X:Z')
      .protect()
      .setWarningOnly(true)
      .setDescription('Auto-computed from Runs and Bugs - do not edit manually.');
  } catch (e) {
    // Protections may be unavailable in some contexts; not fatal.
  }
}

/* ------------------------------------------------------------------ */
/* ▶️ Runs                                                             */
/* ------------------------------------------------------------------ */

/** Runs sheet headers. */
const RUNS_HEADERS = [
  'Run ID', 'Test ID', 'Build / Bucket', 'Tenant URL', 'Tester',
  'Date', 'Status', 'Evidence Link', 'Bug ID', 'Notes'
];

/** Last row covered by Runs validation / conditional formatting. */
const RUNS_LAST_ROW = 2000;

/**
 * Create the Runs sheet and seed RUN-1 with one row per test case.
 * If the sheet already holds more than one data row, the data is preserved and
 * only formatting is refreshed.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Runs sheet.
 */
function buildRunsSheet_(ss) {
  const existing = ss.getSheetByName(SHEETS.RUNS);
  const hasUserData = !!existing && dataRowCount_(existing, 1) > 1;
  const sheet = existing || ss.insertSheet(SHEETS.RUNS);
  ensureSize_(sheet, RUNS_LAST_ROW, RUNS_HEADERS.length);

  if (!hasUserData) {
    sheet.clear();
    const seed = TEST_CASES.map(function (tc) {
      return ['RUN-1', tc[0], '', '', '', '', 'Not Run', '', '', ''];
    });
    if (seed.length) {
      sheet.getRange(2, 1, seed.length, RUNS_HEADERS.length).setValues(seed);
    }
  }
  sheet.getRange(1, 1, 1, RUNS_HEADERS.length).setValues([RUNS_HEADERS]);

  formatRunsSheet_(ss, sheet);
  return sheet;
}

/**
 * Header styling, widths, validation and status colors for the Runs sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Runs sheet.
 */
function formatRunsSheet_(ss, sheet) {
  sheet.getRange(1, 1, 1, RUNS_HEADERS.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.teal)
    .setHorizontalAlignment('center');
  sheet.setFrozenRows(1);

  const widths = [100, 110, 180, 240, 140, 110, 120, 220, 120, 320];
  for (let c = 0; c < widths.length; c++) {
    sheet.setColumnWidth(c + 1, widths[c]);
  }

  applyValidation_(sheet, 2, 2, RUNS_LAST_ROW, rangeValidation_(ss, SHEETS.TESTS, '$A$3:$A$500'));
  applyValidation_(sheet, 7, 2, RUNS_LAST_ROW, listValidation_(ss, 'RunStatus'));

  const dateRule = SpreadsheetApp.newDataValidation()
    .requireDate()
    .setAllowInvalid(false)
    .build();
  const dateColumn = sheet.getRange(2, 6, RUNS_LAST_ROW - 1, 1);
  dateColumn.setDataValidation(dateRule);
  dateColumn.setNumberFormat('yyyy-mm-dd');

  const target = sheet.getRange(2, 1, RUNS_LAST_ROW - 1, RUNS_HEADERS.length);
  sheet.setConditionalFormatRules([
    statusRule_(target, '=$G2="Pass"', COLORS.passBg, null, false),
    statusRule_(target, '=$G2="Fail"', COLORS.failBg, COLORS.failText, true),
    statusRule_(target, '=$G2="Blocked"', COLORS.blockedBg, null, false),
    statusRule_(target, '=$G2="Skipped"', null, COLORS.mutedText, false),
    statusRule_(target, '=$G2="N-A"', null, COLORS.mutedText, false)
  ]);
}

/* ------------------------------------------------------------------ */
/* 🐞 Bugs                                                             */
/* ------------------------------------------------------------------ */

/** Bugs sheet headers. */
const BUGS_HEADERS = [
  'Bug ID', 'Jira', 'Test ID', 'Title', 'Severity', 'Status', 'Found In Run', 'Owner', 'Notes'
];

/** Last row that receives the Jira formula / validation on the Bugs sheet. */
const BUGS_LAST_ROW = 200;

/**
 * Create the Bugs sheet. Existing bug rows are never overwritten.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Bugs sheet.
 */
function buildBugsSheet_(ss) {
  const existing = ss.getSheetByName(SHEETS.BUGS);
  const hasUserData = !!existing && dataRowCount_(existing, 1) > 1;
  const sheet = existing || ss.insertSheet(SHEETS.BUGS);
  ensureSize_(sheet, BUGS_LAST_ROW, BUGS_HEADERS.length);

  if (!hasUserData) {
    sheet.clear();
  }
  sheet.getRange(1, 1, 1, BUGS_HEADERS.length).setValues([BUGS_HEADERS]);

  // The Jira formula renders empty while column A is empty.
  const jira = [];
  for (let r = 2; r <= BUGS_LAST_ROW; r++) {
    jira.push([jiraFormula_('$A' + r)]);
  }
  sheet.getRange(2, 2, jira.length, 1).setFormulas(jira);

  formatBugsSheet_(ss, sheet);
  return sheet;
}

/**
 * Header styling, widths, validation and severity colors for the Bugs sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Bugs sheet.
 */
function formatBugsSheet_(ss, sheet) {
  sheet.getRange(1, 1, 1, BUGS_HEADERS.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.red)
    .setHorizontalAlignment('center');
  sheet.setFrozenRows(1);

  const widths = [120, 120, 110, 320, 120, 120, 120, 140, 320];
  for (let c = 0; c < widths.length; c++) {
    sheet.setColumnWidth(c + 1, widths[c]);
  }

  applyValidation_(sheet, 3, 2, BUGS_LAST_ROW, rangeValidation_(ss, SHEETS.TESTS, '$A$3:$A$500'));
  applyValidation_(sheet, 5, 2, BUGS_LAST_ROW, listValidation_(ss, 'BugSeverity'));
  applyValidation_(sheet, 6, 2, BUGS_LAST_ROW, listValidation_(ss, 'BugStatus'));

  const target = sheet.getRange(2, 1, BUGS_LAST_ROW - 1, BUGS_HEADERS.length);
  sheet.setConditionalFormatRules([
    statusRule_(target, '=$E2="Critical"', '#FFCDD2', COLORS.failText, true),
    statusRule_(target, '=$E2="High"', '#FFE0B2', null, true),
    statusRule_(target, '=$E2="Medium"', '#FFF9C4', null, false),
    statusRule_(target, '=$E2="Low"', '#F1F8E9', null, false),
    statusRule_(target, '=OR($F2="Fixed",$F2="Verified")', null, COLORS.mutedText, false)
  ]);
}

/* ------------------------------------------------------------------ */
/* 📊 Dashboard                                                        */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the Dashboard. Every figure is a formula, so the sheet self-updates
 * as soon as a run or a bug is recorded.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Dashboard sheet.
 */
function buildDashboardSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.DASHBOARD);
  const tc = ref_(SHEETS.TESTS);
  const bugs = ref_(SHEETS.BUGS);

  sheet.getRange('A1').setValue('Test Plan Dashboard');
  sheet.getRange('A1')
    .setFontSize(22)
    .setFontWeight('bold')
    .setFontColor(COLORS.slateDark);

  // ---- KPI block (A3:B10) ----
  const kpiLabels = [
    ['Total Tests'], ['Active Tests'], ['Pass'], ['Fail'],
    ['Blocked'], ['Not Run'], ['% Pass'], ['Open Bugs']
  ];
  const kpiFormulas = [
    ['=COUNTA(' + tc + '$A$3:$A)'],
    ['=COUNTIF(' + tc + '$E$3:$E,"Active")'],
    ['=COUNTIF(' + tc + '$X$3:$X,"Pass")'],
    ['=COUNTIF(' + tc + '$X$3:$X,"Fail")'],
    ['=COUNTIF(' + tc + '$X$3:$X,"Blocked")'],
    ['=COUNTIF(' + tc + '$X$3:$X,"Not Run")'],
    ['=IFERROR($B$5/($B$5+$B$6+$B$7),0)'],
    ['=COUNTIFS(' + bugs + '$A$2:$A,"<>",' + bugs + '$F$2:$F,"<>Fixed",' + bugs + '$F$2:$F,"<>Verified")']
  ];
  sheet.getRange(3, 1, kpiLabels.length, 1).setValues(kpiLabels);
  sheet.getRange(3, 2, kpiFormulas.length, 1).setFormulas(kpiFormulas);

  sheet.getRange(3, 1, kpiLabels.length, 1)
    .setFontWeight('bold')
    .setFontColor(COLORS.slateDark);
  sheet.getRange(3, 2, kpiFormulas.length, 1)
    .setFontSize(14)
    .setFontWeight('bold')
    .setHorizontalAlignment('right');
  sheet.getRange('B9').setNumberFormat('0%');
  sheet.getRange('B6').setFontColor(COLORS.failText);
  sheet.getRange('B5').setFontColor(COLORS.green);

  // ---- Breakdown tables (columns D..K, right of the KPI block) ----
  const ticketRows = buildBreakdownTable_(sheet, 3, 4, 'By Ticket', 'B', CONFIG_LISTS.Ticket);
  const tenantStart = 3 + ticketRows + 3;
  const tenantRows = buildBreakdownTable_(sheet, tenantStart, 4, 'By Tenant', 'G', CONFIG_LISTS.Tenant);

  // ---- Failed & blocked live list ----
  // Placed below both the KPI block and the breakdown tables so the QUERY
  // result always has empty rows to spill into.
  const listRow = Math.max(3 + kpiLabels.length, tenantStart + tenantRows) + 3;
  sheet.getRange(listRow, 1).setValue('Failed & Blocked');
  sheet.getRange(listRow, 1, 1, 4)
    .setBackground(COLORS.failText)
    .setFontColor(COLORS.white)
    .setFontWeight('bold');
  sheet.getRange(listRow + 1, 1).setFormula(
    '=IFERROR(QUERY(' + tc + '$A$3:$Z,"select A,B,D,X where X=\'Fail\' or X=\'Blocked\'",0),"No failures 🎉")'
  );

  sheet.setHiddenGridlines(true);
  sheet.setColumnWidth(1, 180);
  sheet.setColumnWidth(2, 120);
  sheet.setColumnWidth(3, 40);
  for (let c = 4; c <= 11; c++) {
    sheet.setColumnWidth(c, 110);
  }
  return sheet;
}

/**
 * Write a "<dimension> | Total | Pass | Fail | Blocked | Not Run | % Pass |
 * Progress" table driven by COUNTIF/COUNTIFS over a TestCases column.
 * @param {Sheet} sheet The Dashboard sheet.
 * @param {number} startRow 1-based row of the section title.
 * @param {number} startCol 1-based column of the table.
 * @param {string} title Section title.
 * @param {string} column TestCases column letter holding the dimension.
 * @param {!Array<string>} values Dimension values, one per row.
 * @return {number} Number of rows consumed (title + header + values).
 */
function buildBreakdownTable_(sheet, startRow, startCol, title, column, values) {
  const tc = ref_(SHEETS.TESTS);
  const headers = ['Ticket', 'Total', 'Pass', 'Fail', 'Blocked', 'Not Run', '% Pass', 'Progress'];
  headers[0] = title;

  sheet.getRange(startRow, startCol, 1, headers.length).setValues([headers]);
  sheet.getRange(startRow, startCol, 1, headers.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.blue)
    .setHorizontalAlignment('center');

  const dim = colLetter_(startCol);
  const pctCol = colLetter_(startCol + 6);
  const src = tc + '$' + column + '$3:$' + column;
  const statusSrc = tc + '$X$3:$X';

  const rows = values.map(function (value, i) {
    const r = startRow + 1 + i;
    return [
      value,
      '=COUNTIF(' + src + ',$' + dim + r + ')',
      '=COUNTIFS(' + src + ',$' + dim + r + ',' + statusSrc + ',"Pass")',
      '=COUNTIFS(' + src + ',$' + dim + r + ',' + statusSrc + ',"Fail")',
      '=COUNTIFS(' + src + ',$' + dim + r + ',' + statusSrc + ',"Blocked")',
      '=COUNTIFS(' + src + ',$' + dim + r + ',' + statusSrc + ',"Not Run")',
      '=IFERROR(' + colLetter_(startCol + 2) + r + '/' + colLetter_(startCol + 1) + r + ',0)',
      '=SPARKLINE($' + pctCol + r + ',{"charttype","bar";"max",1;"color1","#2E7D32"})'
    ];
  });

  if (rows.length) {
    // Column 1 is a literal label; the rest are formulas.
    const labels = rows.map(function (row) {
      return [row[0]];
    });
    const formulas = rows.map(function (row) {
      return row.slice(1);
    });
    sheet.getRange(startRow + 1, startCol, labels.length, 1).setValues(labels);
    sheet.getRange(startRow + 1, startCol + 1, formulas.length, formulas[0].length).setFormulas(formulas);
    sheet.getRange(startRow + 1, startCol + 6, rows.length, 1).setNumberFormat('0%');
  }

  return rows.length + 1;
}

/* ------------------------------------------------------------------ */
/* 🎯 Coverage                                                         */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the Coverage sheet with two COUNTIFS matrices:
 * Pack Type x Phase and Feature x Tenant.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Coverage sheet.
 */
function buildCoverageSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.COVERAGE);

  sheet.getRange('A1').setValue('Coverage Matrices');
  sheet.getRange('A1').setFontSize(18).setFontWeight('bold').setFontColor(COLORS.slateDark);

  const firstRows = buildCoverageMatrix_(
    sheet, 3, 1, 'Pack Type \\ Phase', 'K', CONFIG_LISTS.PackType, 'I', CONFIG_LISTS.Phase);

  buildCoverageMatrix_(
    sheet, 3 + firstRows + 3, 1, 'Feature \\ Tenant', 'F', CONFIG_LISTS.Feature, 'G', CONFIG_LISTS.Tenant);

  sheet.setHiddenGridlines(true);
  sheet.setColumnWidth(1, 180);
  return sheet;
}

/**
 * Write a single COUNTIFS matrix plus a white-to-green gradient.
 * @param {Sheet} sheet The Coverage sheet.
 * @param {number} startRow 1-based header row of the matrix.
 * @param {number} startCol 1-based column of the row labels.
 * @param {string} title Corner label.
 * @param {string} rowColumn TestCases column letter for the row dimension.
 * @param {!Array<string>} rowValues Row dimension values.
 * @param {string} colColumn TestCases column letter for the column dimension.
 * @param {!Array<string>} colValues Column dimension values.
 * @return {number} Number of rows consumed (header + values).
 */
function buildCoverageMatrix_(sheet, startRow, startCol, title, rowColumn, rowValues, colColumn, colValues) {
  const tc = ref_(SHEETS.TESTS);
  const header = [title].concat(colValues);
  sheet.getRange(startRow, startCol, 1, header.length).setValues([header]);
  sheet.getRange(startRow, startCol, 1, header.length)
    .setFontWeight('bold')
    .setFontColor(COLORS.white)
    .setBackground(COLORS.purple)
    .setHorizontalAlignment('center')
    .setWrap(true);

  const labelLetter = colLetter_(startCol);
  const labels = rowValues.map(function (value) {
    return [value];
  });
  sheet.getRange(startRow + 1, startCol, labels.length, 1).setValues(labels);
  sheet.getRange(startRow + 1, startCol, labels.length, 1).setFontWeight('bold');

  const formulas = rowValues.map(function (unusedRowValue, r) {
    const rowIndex = startRow + 1 + r;
    return colValues.map(function (unusedColValue, c) {
      const colLetterHeader = colLetter_(startCol + 1 + c);
      return '=COUNTIFS(' + tc + '$' + rowColumn + '$3:$' + rowColumn + ',$' + labelLetter + rowIndex + ',' +
        tc + '$' + colColumn + '$3:$' + colColumn + ',' + colLetterHeader + '$' + startRow + ')';
    });
  });

  if (formulas.length) {
    sheet.getRange(startRow + 1, startCol + 1, formulas.length, colValues.length).setFormulas(formulas);
  }

  const body = sheet.getRange(startRow + 1, startCol + 1, rowValues.length, colValues.length);
  body.setHorizontalAlignment('center');

  const gradient = SpreadsheetApp.newConditionalFormatRule()
    .setGradientMinpoint('#FFFFFF')
    .setGradientMidpointWithValue('#C8E6C9', SpreadsheetApp.InterpolationType.PERCENTILE, '50')
    .setGradientMaxpoint('#2E7D32')
    .setRanges([body])
    .build();
  const rules = sheet.getConditionalFormatRules();
  rules.push(gradient);
  sheet.setConditionalFormatRules(rules);

  for (let c = 0; c < colValues.length; c++) {
    sheet.setColumnWidth(startCol + 1 + c, 120);
  }
  return rowValues.length + 1;
}

/* ------------------------------------------------------------------ */
/* 👁️ View sheets                                                      */
/* ------------------------------------------------------------------ */

/** Read-only QUERY views: [sheet name, where clause]. */
const VIEW_DEFS = [
  [SHEETS.V_MARKETPLACE, "G='Marketplace' or H contains 'Marketplace'"],
  [SHEETS.V_MANAGED, "G='Managed' or H contains 'Managed'"],
  [SHEETS.V_CONNECTUS, "G='Connectus' or H contains 'Connectus'"],
  [SHEETS.V_CI, "G='CI'"]
];

/**
 * Rebuild the four read-only 👁️ view sheets.
 * @param {Spreadsheet} ss The spreadsheet.
 */
function buildViewSheets_(ss) {
  for (let i = 0; i < VIEW_DEFS.length; i++) {
    buildViewSheet_(ss, VIEW_DEFS[i][0], VIEW_DEFS[i][1]);
  }
}

/**
 * Rebuild a single view sheet holding one QUERY formula.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} name Sheet name.
 * @param {string} where QUERY where-clause (without the "where" keyword).
 * @return {Sheet} The view sheet.
 */
function buildViewSheet_(ss, name, where) {
  const sheet = resetSheet_(ss, name);
  const tc = ref_(SHEETS.TESTS);

  sheet.getRange('A1').setFormula(
    '=IFERROR(QUERY(' + tc + '$A$2:$Z,"select A,B,D,I,K,L,N,R,S,X where ' + where + '",1),"No matching tests")'
  );

  sheet.getRange('M1')
    .setValue('⚠️ Read-only — auto-generated from ' + SHEETS.TESTS + '. Edit the source sheet instead.')
    .setFontWeight('bold')
    .setFontColor(COLORS.failText);

  sheet.setFrozenRows(1);
  sheet.setColumnWidth(1, 90);
  sheet.setColumnWidth(2, 110);
  sheet.setColumnWidth(3, 320);
  for (let c = 4; c <= 10; c++) {
    sheet.setColumnWidth(c, 140);
  }
  return sheet;
}

/* ------------------------------------------------------------------ */
/* 📖 README                                                           */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the README cover page.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The README sheet.
 */
function buildReadmeSheet_(ss) {
  const sheet = resetSheet_(ss, SHEETS.README);
  ensureSize_(sheet, 60, 8);

  // [text, fontSize, bold, background, fontColor]
  const lines = [
    ['🧪 Connectus Test Plan', 26, true, COLORS.slateDark, COLORS.white],
    ['Single source of truth for the test cases, setups, runs and bugs of this feature.', 11, false, null, null],
    ['', 10, false, null, null],

    ['Purpose', 16, true, COLORS.blue, COLORS.white],
    ['The workbook is generated from code (data.gs + build.gs). Test cases, setups and dropdown ' +
      'vocabularies live in data.gs; everything you see here is produced by buildWorkbook().', 11, false, null, null],
    ['', 10, false, null, null],

    ['Tabs', 16, true, COLORS.blue, COLORS.white],
    ['⚙️ Config — the vocabulary of every dropdown. One column per category, exposed as the named ' +
      'range List_<Category>. Add a value here and every dropdown picks it up immediately.', 11, false, null, null],
    ['🧱 Setup — the environments/builds/PRs the tests depend on. "# Tests" and "Blocked Tests" are live counts.',
      11, false, null, null],
    ['🧪 TestCases — the main sheet. Two header rows: coloured block banners (Identity / Classification / ' +
      'Execution / Status) above the real column headers. Columns X:Z are auto-computed from Runs and Bugs.',
      11, false, null, null],
    ['▶️ Runs — one row per (test, run). This is where testers record results. Nothing else is written by hand.',
      11, false, null, null],
    ['🐞 Bugs — bugs found while executing runs. Column B renders a Jira link automatically.', 11, false, null, null],
    ['📊 Dashboard — live KPIs plus per-ticket and per-tenant breakdowns; entirely formula driven.',
      11, false, null, null],
    ['🎯 Coverage — Pack Type × Phase and Feature × Tenant matrices. White cells are coverage gaps.',
      11, false, null, null],
    ['👁️ Marketplace / Managed / Connectus / CI — read-only QUERY views over TestCases.', 11, false, null, null],
    ['', 10, false, null, null],

    ['Test ID prefixes', 16, true, COLORS.blue, COLORS.white],
    ['DP  — Derived Packs', 11, false, null, null],
    ['CMN — Common-Base', 11, false, null, null],
    ['RN  — Release Notes', 11, false, null, null],
    ['NC  — Notification Center', 11, false, null, null],
    ['CSP — CSP BC Validation', 11, false, null, null],
    ['', 10, false, null, null],

    ['Golden rules', 16, true, COLORS.red, COLORS.white],
    ['1. Never delete a test row — set Active = "Deprecated" instead.', 11, true, null, null],
    ['2. Never reuse a test ID. New tests always take the next free number for their prefix.', 11, true, null, null],
    ['3. To add a category value, edit ⚙️ Config — never type a free value into a dropdown column.',
      11, true, null, null],
    ['4. To start a new execution cycle, use 🧪 Test Plan ▸ 🔄 Start New Run (it copies every Active test ' +
      'ID into ▶️ Runs under a new Run ID).', 11, true, null, null],
    ['5. Columns X:Z of 🧪 TestCases are computed — do not overwrite them.', 11, true, null, null],
    ['', 10, false, null, null],

    ['Status legend', 16, true, COLORS.blue, COLORS.white],
    ['Pass — light green background', 11, false, COLORS.passBg, null],
    ['Fail — light red background, bold dark red text', 11, true, COLORS.failBg, COLORS.failText],
    ['Blocked — light orange background', 11, false, COLORS.blockedBg, null],
    ['Skipped / N-A — grey text', 11, false, null, COLORS.mutedText],
    ['Deprecated test — grey background, struck through', 11, false, COLORS.deprecatedBg, COLORS.mutedText],
    ['', 10, false, null, null],

    ['Bugs Jira formula', 16, true, COLORS.blue, COLORS.white],
    ['Column B of 🐞 Bugs is pre-filled for rows 2:200 with: ' +
      '=IF($A2="","",HYPERLINK("' + JIRA_BASE_URL + '"&$A2,$A2)) — it stays empty until you type a bug key in A.',
      11, false, null, null],
    ['', 10, false, null, null],

    ['How to re-run the builder', 16, true, COLORS.green, COLORS.white],
    ['1. Edit data.gs (add test cases, setups or dropdown values).', 11, false, null, null],
    ['2. Menu 🧪 Test Plan ▸ 🏗️ Rebuild Workbook (or run buildWorkbook() in the Apps Script editor).',
      11, false, null, null],
    ['3. The rebuild is safe: ▶️ Runs and 🐞 Bugs keep any data already entered; every other tab is regenerated.',
      11, false, null, null],
    ['4. Menu 🧪 Test Plan ▸ 🎨 Reapply Formatting refreshes styling only, without touching data.',
      11, false, null, null]
  ];

  const values = lines.map(function (line) {
    return [line[0]];
  });
  sheet.getRange(1, 1, values.length, 1).setValues(values);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const range = sheet.getRange(i + 1, 1, 1, 8);
    range.merge();
    const cell = sheet.getRange(i + 1, 1);
    cell.setFontSize(line[1]).setFontWeight(line[2] ? 'bold' : 'normal').setWrap(true);
    if (line[3]) {
      range.setBackground(line[3]);
    }
    if (line[4]) {
      cell.setFontColor(line[4]);
    }
    sheet.setRowHeight(i + 1, line[1] >= 16 ? 32 : 22);
  }

  sheet.setColumnWidth(1, 220);
  for (let c = 2; c <= 8; c++) {
    sheet.setColumnWidth(c, 110);
  }
  sheet.setHiddenGridlines(true);
  return sheet;
}

/* ------------------------------------------------------------------ */
/* Menu actions                                                        */
/* ------------------------------------------------------------------ */

/**
 * Append a new test row to 🧪 TestCases with the next free ID for a prefix,
 * copying formulas and validation down from the row above.
 */
function addTestRow() {
  const ui = SpreadsheetApp.getUi();
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(SHEETS.TESTS);
  if (!sheet) {
    ui.alert('Sheet "' + SHEETS.TESTS + '" not found. Run 🏗️ Rebuild Workbook first.');
    return;
  }

  const response = ui.prompt(
    'Add Test Row',
    'ID prefix (' + ID_PREFIXES.join(' / ') + '):',
    ui.ButtonSet.OK_CANCEL);
  if (response.getSelectedButton() !== ui.Button.OK) {
    return;
  }

  const prefix = String(response.getResponseText()).trim().toUpperCase();
  if (ID_PREFIXES.indexOf(prefix) === -1) {
    ui.alert('Unknown prefix "' + prefix + '". Allowed: ' + ID_PREFIXES.join(', '));
    return;
  }

  const lastRow = Math.max(TC_FIRST_ROW, sheet.getLastRow());
  const newRow = lastRow + 1;
  const newId = nextTestId_(sheet, prefix);

  // Copy the previous row so formulas, validation and formatting come along.
  sheet.getRange(lastRow, 1, 1, TC_HEADERS.length)
    .copyTo(sheet.getRange(newRow, 1, 1, TC_HEADERS.length));

  // Clear the copied content, keeping only the generated formulas.
  sheet.getRange(newRow, 1, 1, TC_HEADERS.length).clearContent();
  sheet.getRange(newRow, 1).setValue(newId);
  sheet.getRange(newRow, 3).setFormula(jiraFormula_('$B' + newRow));
  sheet.getRange(newRow, 5).setValue('Active');
  sheet.getRange(newRow, 24).setFormula(latestRunFormula_('G', newRow, '"Not Run"'));
  sheet.getRange(newRow, 25).setFormula(latestRunFormula_('A', newRow, '""'));
  sheet.getRange(newRow, 26).setFormula(openBugFormula_(newRow));

  sheet.setRowHeight(newRow, 22);
  sheet.setActiveRange(sheet.getRange(newRow, 2));
  ss.toast('Added ' + newId + ' on row ' + newRow + '.', '🧪 Test Plan', 5);
}

/**
 * Compute the next free ID for a prefix, e.g. "DP-043".
 * @param {Sheet} sheet The TestCases sheet.
 * @param {string} prefix One of ID_PREFIXES.
 * @return {string} The next ID.
 */
function nextTestId_(sheet, prefix) {
  const lastRow = sheet.getLastRow();
  let max = 0;
  if (lastRow >= TC_FIRST_ROW) {
    const ids = sheet.getRange(TC_FIRST_ROW, 1, lastRow - TC_FIRST_ROW + 1, 1).getValues();
    for (let i = 0; i < ids.length; i++) {
      const match = /^([A-Z]+)-(\d+)$/.exec(String(ids[i][0]).trim());
      if (match && match[1] === prefix) {
        max = Math.max(max, Number(match[2]));
      }
    }
  }
  const next = String(max + 1);
  const padded = next.length >= 3 ? next : ('000' + next).slice(-3);
  return prefix + '-' + padded;
}

/**
 * Append one ▶️ Runs row per Active test case under a brand-new Run ID.
 */
function startNewRun() {
  const ui = SpreadsheetApp.getUi();
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const runs = ss.getSheetByName(SHEETS.RUNS);
  const tests = ss.getSheetByName(SHEETS.TESTS);
  if (!runs || !tests) {
    ui.alert('Runs or TestCases sheet is missing. Run 🏗️ Rebuild Workbook first.');
    return;
  }

  const runId = nextRunId_(runs);
  const response = ui.prompt(
    'Start New Run',
    'Label for ' + runId + ' (build / bucket, optional):',
    ui.ButtonSet.OK_CANCEL);
  if (response.getSelectedButton() !== ui.Button.OK) {
    return;
  }
  const label = String(response.getResponseText()).trim();

  const lastTestRow = tests.getLastRow();
  if (lastTestRow < TC_FIRST_ROW) {
    ui.alert('There are no test cases to run.');
    return;
  }

  const data = tests.getRange(TC_FIRST_ROW, 1, lastTestRow - TC_FIRST_ROW + 1, 5).getValues();
  const rows = [];
  for (let i = 0; i < data.length; i++) {
    const id = String(data[i][0]).trim();
    const active = String(data[i][4]).trim();
    if (id && active !== 'Deprecated') {
      rows.push([runId, id, label, '', '', '', 'Not Run', '', '', '']);
    }
  }
  if (!rows.length) {
    ui.alert('No Active test cases found.');
    return;
  }

  const startRow = Math.max(2, runs.getLastRow() + 1);
  runs.getRange(startRow, 1, rows.length, RUNS_HEADERS.length).setValues(rows);
  runs.setActiveRange(runs.getRange(startRow, 1));
  ss.setActiveSheet(runs);
  ss.toast('Created ' + runId + ' with ' + rows.length + ' rows.', '🧪 Test Plan', 5);
}

/**
 * Compute the next run identifier, e.g. "RUN-3".
 * @param {Sheet} runs The Runs sheet.
 * @return {string} The next Run ID.
 */
function nextRunId_(runs) {
  const lastRow = runs.getLastRow();
  let max = 0;
  if (lastRow >= 2) {
    const ids = runs.getRange(2, 1, lastRow - 1, 1).getValues();
    for (let i = 0; i < ids.length; i++) {
      const match = /^RUN-(\d+)$/.exec(String(ids[i][0]).trim());
      if (match) {
        max = Math.max(max, Number(match[1]));
      }
    }
  }
  return 'RUN-' + (max + 1);
}
