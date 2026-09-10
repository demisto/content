/**
 * Test Plan – LITE workbook builder.
 *
 * A deliberately small alternative to `build.gs`: three visible sheets
 * (📋 Overview, 🧪 Tests, 🧱 Setup) plus one hidden ⚙️ Config sheet that backs
 * the dropdowns. All data comes from `data.gs` (CONFIG_LISTS, SETUPS,
 * TEST_CASES) – `data.gs` is shared and must not be modified.
 *
 * ── Running it ──────────────────────────────────────────────────────────────
 * Run `buildLiteWorkbook()` from the Apps Script editor, or use the
 * "🧪 Test Plan (Lite)" menu. The builder is idempotent: running it twice in a
 * row must never throw.
 *
 * ── Coexisting with build.gs ────────────────────────────────────────────────
 * Every top-level name in this file is prefixed (`LITE_` for constants,
 * `lite`/`_lite_` for functions) so the file can live in the SAME Apps Script
 * project as `build.gs` without a single collision. Named ranges are prefixed
 * `LT_` for the same reason.
 *
 * The ONE thing Apps Script cannot share is the special `onOpen()` trigger:
 * a project may only declare it once. This file therefore exposes
 * `liteOnOpen()` instead. Pick one of:
 *   (a) keep only one of the two builders in the project, and rename
 *       `liteOnOpen` to `onOpen` if that one is this file; or
 *   (b) keep both and call `liteOnOpen()` from `build.gs`'s `onOpen()`.
 * As a safety net `buildLiteWorkbook()` installs the menu itself, so the menu
 * shows up as soon as the builder has been run once in the session.
 */

/* eslint-disable no-unused-vars */

/** Canonical sheet names. Every formula in this file is derived from these. */
const LITE_SHEETS = {
  OVERVIEW: '📋 Overview',
  TESTS: '🧪 Tests',
  SETUP: '🧱 Setup',
  CONFIG: '⚙️ Config'
};

/** Left-to-right tab order for the lite sheets. */
const LITE_SHEET_ORDER = [
  LITE_SHEETS.OVERVIEW,
  LITE_SHEETS.TESTS,
  LITE_SHEETS.SETUP,
  LITE_SHEETS.CONFIG
];

/** Prefix used for every named range created by this builder. */
const LITE_NR_PREFIX = 'LT_';

/** Neutral colors shared by all three sheets. */
const LITE_UI = {
  white: '#FFFFFF',
  ink: '#212121',
  dark: '#263238',
  darker: '#1B2327',
  muted: '#9E9E9E',
  line: '#CFD8DC',
  passBg: '#E8F5E9',
  failBg: '#FFEBEE',
  failText: '#B71C1C',
  blockedBg: '#FFF3E0',
  green: '#2E7D32',
  amber: '#EF6C00',
  grey: '#ECEFF1'
};

/**
 * Color families used to paint the test blocks.
 * Each family carries three weights (50 = data rows, 100 = column headers,
 * 700 = block header) plus an `alt` triple used to alternate between
 * consecutive blocks that belong to the same ticket.
 */
const LITE_COLORS = [
  {
    name: 'Blue', emoji: '🔵',
    c50: '#E3F2FD', c100: '#BBDEFB', c700: '#1976D2',
    alt: { c50: '#E8F0FE', c100: '#C5D9F7', c700: '#1565C0' }
  },
  {
    name: 'Cyan', emoji: '🩵',
    c50: '#E0F7FA', c100: '#B2EBF2', c700: '#0097A7',
    alt: { c50: '#E0F2F1', c100: '#B2DFDB', c700: '#00796B' }
  },
  {
    name: 'Purple', emoji: '🟣',
    c50: '#F3E5F5', c100: '#E1BEE7', c700: '#7B1FA2',
    alt: { c50: '#EDE7F6', c100: '#D1C4E9', c700: '#5E35B1' }
  },
  {
    name: 'Orange', emoji: '🟠',
    c50: '#FFF3E0', c100: '#FFE0B2', c700: '#EF6C00',
    alt: { c50: '#FBE9E7', c100: '#FFCCBC', c700: '#D84315' }
  },
  {
    name: 'Green', emoji: '🟢',
    c50: '#E8F5E9', c100: '#C8E6C9', c700: '#2E7D32',
    alt: { c50: '#F1F8E9', c100: '#DCEDC8', c700: '#558B2F' }
  },
  {
    name: 'Red', emoji: '🔴',
    c50: '#FFEBEE', c100: '#FFCDD2', c700: '#C62828',
    alt: { c50: '#FCE4EC', c100: '#F8BBD0', c700: '#AD1457' }
  },
  {
    name: 'Indigo', emoji: '🔷',
    c50: '#E8EAF6', c100: '#C5CAE9', c700: '#303F9F',
    alt: { c50: '#E3E7F1', c100: '#B9C2E0', c700: '#283593'
    }
  },
  {
    name: 'Amber', emoji: '🟡',
    c50: '#FFFDE7', c100: '#FFF9C4', c700: '#F9A825',
    alt: { c50: '#FFF8E1', c100: '#FFECB3', c700: '#FF8F00' }
  }
];

/**
 * Explicit family assignment. Keys are matched against the block's ticket
 * first and its feature second, so `Common-Base` gets its own visual identity
 * even though it belongs to CIAC-17084. Anything unknown falls back to the
 * palette, cycled by order of first appearance.
 */
const LITE_FAMILY_BY_KEY = {
  'Common-Base': 2,   // purple – visually distinct sub-feature of CIAC-17084
  'CIAC-17084': 0,    // blue
  'CIAC-17085': 3,    // orange
  'CIAC-17086': 4,    // green
  'CIAC-17274': 5     // red
};

/** Column headers of the 🧪 Tests sheet. */
const LITE_TEST_HEADERS = [
  'ID',
  'What We Test',
  'Expected Result',
  'Where',
  'Setup',
  'Priority',
  'Status',
  'Notes / Evidence'
];

/** Column widths of the 🧪 Tests sheet, in the same order as the headers. */
const LITE_TEST_WIDTHS = [85, 420, 520, 130, 105, 95, 125, 340];

/** 1-based Status column index on the 🧪 Tests sheet. */
const LITE_STATUS_COL = 7;

/** Default value written into every Status cell. */
const LITE_DEFAULT_STATUS = 'Not Run';

/** Height of a block header row / a data row, in pixels. */
const LITE_BLOCK_HEADER_HEIGHT = 28;
const LITE_DATA_ROW_HEIGHT = 21;

/** Cosmetic rewrites applied when turning raw enum values into block labels. */
const LITE_LABEL_ALIASES = {
  'Installed+Instance': 'Installed + Instance',
  'Installed-NoInstance': 'Installed, no instance',
  'Not-Installed': 'Not installed',
  'Post-Optin + New Version': 'Post-Optin (new version)',
  'Derived Packs': 'Derived Packs',
  'CSP BC Validation': 'CSP BC Validation'
};

/** Values that carry no information and are dropped from block labels. */
const LITE_EMPTY_LABEL_VALUES = ['', 'N-A', 'N/A', 'NA'];

/** Setup ref that is so common it is omitted from block labels. */
const LITE_DEFAULT_SETUP = 'SETUP-01';

/* ------------------------------------------------------------------ */
/* Generic helpers (all distinct from build.gs)                        */
/* ------------------------------------------------------------------ */

/**
 * Quote a sheet name for use inside an A1 formula.
 * @param {string} name Sheet name (may contain emoji / spaces).
 * @return {string} e.g. `'🧪 Tests'!`
 */
function liteRef_(name) {
  return "'" + String(name).replace(/'/g, "''") + "'!";
}

/**
 * Fetch a sheet by name, creating it when missing.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} name Sheet name.
 * @return {Sheet} The existing or newly created sheet.
 */
function liteGetOrCreateSheet_(ss, name) {
  return ss.getSheetByName(name) || ss.insertSheet(name);
}

/**
 * Grow a sheet so it has at least the requested number of rows and columns.
 * @param {Sheet} sheet Target sheet.
 * @param {number} rows Minimum row count.
 * @param {number} cols Minimum column count.
 */
function liteEnsureSize_(sheet, rows, cols) {
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
 * Remove every row group from a sheet.
 *
 * There is no "remove all groups" API, and `shiftRowGroupDepth(-1)` throws on
 * ranges that carry no group. The safe approach used here walks the sheet and
 * removes the outermost group found on each row via `getRowGroup()`, repeating
 * while the depth is still positive. Every call is guarded, so a rebuild can
 * never fail because of a stale group.
 * @param {Sheet} sheet Target sheet.
 */
function liteRemoveRowGroups_(sheet) {
  const maxRows = sheet.getMaxRows();
  for (let row = 1; row <= maxRows; row++) {
    let depth = 0;
    try {
      depth = sheet.getRowGroupDepth(row);
    } catch (e) {
      depth = 0;
    }
    let guard = 0;
    while (depth > 0 && guard < 10) {
      try {
        const group = sheet.getRowGroup(row, depth);
        if (group) {
          group.remove();
        }
      } catch (e) {
        break;
      }
      guard++;
      try {
        depth = sheet.getRowGroupDepth(row);
      } catch (e) {
        depth = 0;
      }
    }
  }
}

/**
 * Return an empty sheet with the given name.
 *
 * The sheet is wiped in place rather than deleted and recreated: deleting a
 * sheet turns every cross-sheet reference pointing at it into a permanent
 * `#REF!`, which would break the workbook on the second run. Merges, filters,
 * bandings, freezes and row groups are all cleared so a rebuild never hits an
 * "already exists" error.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} name Sheet name.
 * @return {Sheet} A blank sheet.
 */
function liteResetSheet_(ss, name) {
  const sheet = liteGetOrCreateSheet_(ss, name);

  // Freezes are dropped first: a frozen row/column boundary that cuts through
  // a merge blocks both breakApart() and the later setFrozenRows() call.
  sheet.setFrozenRows(0);
  sheet.setFrozenColumns(0);

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

  try {
    sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns()).breakApart();
  } catch (e) {
    // Nothing merged.
  }

  liteRemoveRowGroups_(sheet);
  return sheet;
}

/**
 * Convert a 1-based column index to its A1 letter.
 * @param {number} index 1-based column index.
 * @return {string} Column letter(s).
 */
function liteColLetter_(index) {
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
 * Build a data-validation rule bound to one of the `LT_` named ranges.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {string} listKey Key of CONFIG_LISTS.
 * @return {DataValidation|null} The rule, or null when the range is missing.
 */
function liteListValidation_(ss, listKey) {
  const range = ss.getRangeByName(LITE_NR_PREFIX + listKey);
  if (!range) {
    return null;
  }
  return SpreadsheetApp.newDataValidation()
    .requireValueInRange(range, true)
    .setAllowInvalid(false)
    .build();
}

/**
 * Apply a validation rule to a range, ignoring a missing rule.
 * @param {Range} range Target range.
 * @param {DataValidation|null} rule Rule to apply.
 */
function liteApplyValidation_(range, rule) {
  if (rule) {
    range.setDataValidation(rule);
  }
}

/**
 * Build a conditional-format rule from a custom formula.
 * @param {Range} range Range the rule applies to.
 * @param {string} formula Custom formula.
 * @param {?string} background Background color, or null to leave it alone.
 * @param {?string} fontColor Font color, or null to leave it alone.
 * @param {boolean} bold Whether to bold the text.
 * @return {ConditionalFormatRule} The built rule.
 */
function liteFormulaRule_(range, formula, background, fontColor, bold) {
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

/**
 * Move the lite sheets into LITE_SHEET_ORDER, leaving foreign sheets alone.
 * @param {Spreadsheet} ss The spreadsheet.
 */
function liteOrderSheets_(ss) {
  for (let i = 0; i < LITE_SHEET_ORDER.length; i++) {
    const sheet = ss.getSheetByName(LITE_SHEET_ORDER[i]);
    if (sheet && !sheet.isSheetHidden()) {
      ss.setActiveSheet(sheet);
      ss.moveActiveSheet(i + 1);
    }
  }
  const first = ss.getSheetByName(LITE_SHEETS.OVERVIEW);
  if (first) {
    ss.setActiveSheet(first);
  }
}

/* ------------------------------------------------------------------ */
/* ⚙️ Config (hidden)                                                  */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the hidden Config sheet: one column per CONFIG_LISTS key plus a
 * named range `LT_<Key>` covering rows 2..200, so appending a value in
 * `data.gs` is picked up by every dropdown automatically.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Config sheet.
 */
function liteBuildConfigSheet_(ss) {
  const sheet = liteResetSheet_(ss, LITE_SHEETS.CONFIG);
  const keys = Object.keys(CONFIG_LISTS);
  liteEnsureSize_(sheet, 200, Math.max(keys.length, 1));

  sheet.getRange(1, 1, 1, keys.length).setValues([keys]);

  for (let c = 0; c < keys.length; c++) {
    const values = CONFIG_LISTS[keys[c]];
    const matrix = values.map(function (v) {
      return [v];
    });
    if (matrix.length) {
      sheet.getRange(2, c + 1, matrix.length, 1).setValues(matrix);
    }
  }

  sheet.getRange(1, 1, 1, keys.length)
    .setFontWeight('bold')
    .setFontColor(LITE_UI.white)
    .setBackground(LITE_UI.dark)
    .setHorizontalAlignment('center');

  sheet.setFrozenRows(1);
  for (let c = 1; c <= keys.length; c++) {
    sheet.setColumnWidth(c, 150);
  }

  liteCreateNamedRanges_(ss, sheet, keys);
  sheet.hideSheet();
  return sheet;
}

/**
 * (Re)create one `LT_<Key>` named range per Config column.
 * Same-named ranges are removed first so a rebuild never duplicates them.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Config sheet.
 * @param {!Array<string>} keys CONFIG_LISTS keys in column order.
 */
function liteCreateNamedRanges_(ss, sheet, keys) {
  const wanted = {};
  for (let i = 0; i < keys.length; i++) {
    wanted[LITE_NR_PREFIX + keys[i]] = true;
  }

  const existing = ss.getNamedRanges();
  for (let i = 0; i < existing.length; i++) {
    if (wanted[existing[i].getName()]) {
      existing[i].remove();
    }
  }

  for (let c = 0; c < keys.length; c++) {
    const letter = liteColLetter_(c + 1);
    ss.setNamedRange(LITE_NR_PREFIX + keys[c], sheet.getRange(letter + '2:' + letter + '200'));
  }
}

/* ------------------------------------------------------------------ */
/* Block derivation                                                    */
/* ------------------------------------------------------------------ */

/**
 * Indices of the TEST_CASES columns this file reads. Kept in one place so a
 * column re-order in `data.gs` only has to be reflected here.
 */
const LITE_TC = {
  ID: 0,
  TICKET: 1,
  TITLE: 2,
  FEATURE: 4,
  TENANT: 5,
  TENANT_SCOPE: 6,
  PHASE: 7,
  PACK_STATE: 8,
  PRIORITY: 12,
  SETUP_REF: 14,
  EXPECTED: 17
};

/**
 * True when a value carries no information and should be skipped in a label.
 * @param {*} value Raw cell value.
 * @return {boolean} Whether the value is meaningless.
 */
function liteIsEmptyValue_(value) {
  return LITE_EMPTY_LABEL_VALUES.indexOf(String(value == null ? '' : value).trim()) !== -1;
}

/**
 * Human-friendly rendering of a single enum value.
 * @param {*} value Raw cell value.
 * @return {string} The prettified value.
 */
function litePrettyValue_(value) {
  const raw = String(value == null ? '' : value).trim();
  return LITE_LABEL_ALIASES[raw] || raw;
}

/**
 * Turn one TEST_CASES row into the 8-column layout of the 🧪 Tests sheet.
 * `Where` prefers Tenant Scope over Tenant when the test spans several
 * surfaces, because "Connectus & Marketplace" says more than "Multi".
 * @param {!Array<*>} src A row from TEST_CASES.
 * @return {!Array<*>} An 8-cell row.
 */
function liteTestRow_(src) {
  const tenant = String(src[LITE_TC.TENANT] || '').trim();
  const scope = String(src[LITE_TC.TENANT_SCOPE] || '').trim();
  const where = tenant === 'Multi' && scope ? scope : tenant;
  return [
    src[LITE_TC.ID],
    src[LITE_TC.TITLE],
    src[LITE_TC.EXPECTED],
    where,
    src[LITE_TC.SETUP_REF],
    src[LITE_TC.PRIORITY],
    LITE_DEFAULT_STATUS,
    ''
  ];
}

/**
 * Readable label for a block, built from its grouping fields.
 * Empty / `N-A` values are dropped, the rest are joined with " · ". The setup
 * ref is appended only when it is not the default one.
 * @param {!Array<*>} src Any TEST_CASES row belonging to the block.
 * @return {string} e.g. "Installed + Instance · Pre-Optin".
 */
function liteBlockLabel_(src) {
  const parts = [];
  const feature = String(src[LITE_TC.FEATURE] || '').trim();
  const candidates = [src[LITE_TC.PACK_STATE], src[LITE_TC.PHASE]];

  // The phase is the most descriptive field there is, so when it is present
  // the feature is redundant noise. When there is no phase the feature is
  // what makes the block recognisable, so it leads the label instead.
  if (!liteIsEmptyValue_(feature) && liteIsEmptyValue_(src[LITE_TC.PHASE])) {
    parts.push(litePrettyValue_(feature));
  }

  for (let i = 0; i < candidates.length; i++) {
    if (!liteIsEmptyValue_(candidates[i])) {
      parts.push(litePrettyValue_(candidates[i]));
    }
  }

  const setup = String(src[LITE_TC.SETUP_REF] || '').trim();
  if (setup && setup !== LITE_DEFAULT_SETUP) {
    parts.push(setup);
  }

  if (!parts.length) {
    parts.push(litePrettyValue_(feature) || 'Other');
  }
  return parts.join(' · ');
}

/**
 * Group TEST_CASES into colored blocks.
 *
 * The composite key is `Ticket + Feature + Phase + Pack State + Setup Ref`,
 * and blocks keep the order in which their key first appears in TEST_CASES.
 * Nothing is hardcoded: a new row in `data.gs` lands in the matching block
 * automatically, and a brand-new combination produces a brand-new block.
 * @return {!Array<!Object>} Blocks: {key, ticket, label, colors, rows}.
 */
function liteDeriveBlocks_() {
  const byKey = {};
  const ordered = [];

  for (let i = 0; i < TEST_CASES.length; i++) {
    const src = TEST_CASES[i];
    const key = [
      src[LITE_TC.TICKET],
      src[LITE_TC.FEATURE],
      src[LITE_TC.PHASE],
      src[LITE_TC.PACK_STATE],
      src[LITE_TC.SETUP_REF]
    ].join('|');

    if (!byKey[key]) {
      byKey[key] = {
        key: key,
        ticket: String(src[LITE_TC.TICKET] || '').trim(),
        feature: String(src[LITE_TC.FEATURE] || '').trim(),
        label: liteBlockLabel_(src),
        rows: []
      };
      ordered.push(byKey[key]);
    }
    byKey[key].rows.push(liteTestRow_(src));
  }

  liteAssignBlockColors_(ordered);
  return ordered;
}

/**
 * Assign a color family per ticket (Common-Base gets its own) and alternate
 * between the base and the `alt` shade inside a family, so two consecutive
 * blocks of the same ticket never look identical.
 * @param {!Array<!Object>} blocks Blocks in render order; mutated in place.
 */
function liteAssignBlockColors_(blocks) {
  const familyByGroup = {};
  const seenPerGroup = {};
  let nextFallback = 0;

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const groupKey = LITE_FAMILY_BY_KEY.hasOwnProperty(block.feature) ? block.feature : block.ticket;

    if (!familyByGroup.hasOwnProperty(groupKey)) {
      if (LITE_FAMILY_BY_KEY.hasOwnProperty(groupKey)) {
        familyByGroup[groupKey] = LITE_FAMILY_BY_KEY[groupKey] % LITE_COLORS.length;
      } else {
        familyByGroup[groupKey] = nextFallback % LITE_COLORS.length;
        nextFallback++;
      }
      seenPerGroup[groupKey] = 0;
    }

    const family = LITE_COLORS[familyByGroup[groupKey]];
    const useAlt = seenPerGroup[groupKey] % 2 === 1;
    seenPerGroup[groupKey]++;

    block.familyIndex = familyByGroup[groupKey];
    block.familyName = family.name;
    block.emoji = family.emoji;
    block.colors = useAlt ? family.alt : { c50: family.c50, c100: family.c100, c700: family.c700 };
  }
}

/**
 * Map every ticket to the ID prefixes it uses (CIAC-17084 -> DP, CMN).
 * Used by 📋 Overview, whose only link back to a ticket is the test ID.
 * @return {!Object<string, !Array<string>>} Ticket -> sorted prefixes.
 */
function liteTicketPrefixes_() {
  const map = {};
  for (let i = 0; i < TEST_CASES.length; i++) {
    const ticket = String(TEST_CASES[i][LITE_TC.TICKET] || '').trim();
    const id = String(TEST_CASES[i][LITE_TC.ID] || '').trim();
    const match = /^([A-Za-z]+)-/.exec(id);
    if (!ticket || !match) {
      continue;
    }
    if (!map[ticket]) {
      map[ticket] = [];
    }
    if (map[ticket].indexOf(match[1]) === -1) {
      map[ticket].push(match[1]);
    }
  }
  return map;
}

/* ------------------------------------------------------------------ */
/* 🧪 Tests                                                            */
/* ------------------------------------------------------------------ */

/**
 * Rebuild the 🧪 Tests sheet.
 *
 * Layout: a merged title strip on row 1, then one mini-table per derived
 * block (block header ▸ column headers ▸ data rows ▸ spacer). Only row 1 is
 * frozen and no column is ever frozen, which sidesteps the whole class of
 * "a merge may not straddle the freeze line" errors.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Tests sheet.
 */
function liteBuildTestsSheet_(ss) {
  const sheet = liteResetSheet_(ss, LITE_SHEETS.TESTS);
  const blocks = liteDeriveBlocks_();
  const cols = LITE_TEST_HEADERS.length;

  let totalTests = 0;
  for (let i = 0; i < blocks.length; i++) {
    totalTests += blocks[i].rows.length;
  }

  // title + per block (header + column header + spacer) + data rows + slack
  const neededRows = 1 + blocks.length * 3 + totalTests + 5;
  liteEnsureSize_(sheet, neededRows, cols);

  liteWriteTitleStrip_(sheet, cols, totalTests);

  let row = 2;
  const dataRanges = [];
  for (let i = 0; i < blocks.length; i++) {
    row = liteRenderBlock_(sheet, blocks[i], row, cols, dataRanges);
  }
  const lastRow = Math.max(2, row - 1);

  liteFormatTestsSheet_(ss, sheet, cols, lastRow, dataRanges);
  return sheet;
}

/**
 * Write and style the merged summary strip on row 1.
 * @param {Sheet} sheet The Tests sheet.
 * @param {number} cols Number of columns.
 * @param {number} totalTests Number of test rows rendered below.
 */
function liteWriteTitleStrip_(sheet, cols, totalTests) {
  const range = sheet.getRange(1, 1, 1, cols);
  range.merge();
  range.setValue('  🧪 Connectus Test Plan — ' + totalTests + ' tests');
  range.setBackground(LITE_UI.darker)
    .setFontColor(LITE_UI.white)
    .setFontWeight('bold')
    .setFontSize(14)
    .setHorizontalAlignment('left')
    .setVerticalAlignment('middle');
  sheet.setRowHeight(1, 34);
}

/**
 * Render a single block: header, column headers, data rows and a spacer.
 * @param {Sheet} sheet The Tests sheet.
 * @param {!Object} block A block from liteDeriveBlocks_().
 * @param {number} startRow Row the block starts on.
 * @param {number} cols Number of columns.
 * @param {!Array<!Array<number>>} dataRanges Collector of [firstRow, count]
 *     pairs for the data rows, used later for grouping.
 * @return {number} The first free row after the block's spacer.
 */
function liteRenderBlock_(sheet, block, startRow, cols, dataRanges) {
  const colors = block.colors;

  // 1. Block header – merged across A:H. Because the cells are merged the
  // "<n> tests" suffix cannot be right-aligned separately, so it is baked
  // into a single left-aligned string.
  const headerRange = sheet.getRange(startRow, 1, 1, cols);
  headerRange.merge();
  headerRange.setValue(
    '  ' + block.emoji + ' ' + block.ticket + ' · ' + block.label +
    '   —   ' + block.rows.length + (block.rows.length === 1 ? ' test' : ' tests'));
  headerRange.setBackground(colors.c700)
    .setFontColor(LITE_UI.white)
    .setFontWeight('bold')
    .setFontSize(11)
    .setHorizontalAlignment('left')
    .setVerticalAlignment('middle');
  sheet.setRowHeight(startRow, LITE_BLOCK_HEADER_HEIGHT);

  // 2. Column headers.
  const headerRow = startRow + 1;
  const colHeaderRange = sheet.getRange(headerRow, 1, 1, cols);
  colHeaderRange.setValues([LITE_TEST_HEADERS]);
  colHeaderRange.setBackground(colors.c100)
    .setFontColor(LITE_UI.ink)
    .setFontWeight('bold')
    .setVerticalAlignment('middle')
    .setBorder(null, null, true, null, null, null, LITE_UI.dark,
      SpreadsheetApp.BorderStyle.SOLID);
  sheet.setRowHeight(headerRow, LITE_DATA_ROW_HEIGHT + 3);

  // 3. Data rows – very pale background so each block reads as its own table.
  const firstDataRow = headerRow + 1;
  const dataRange = sheet.getRange(firstDataRow, 1, block.rows.length, cols);
  dataRange.setValues(block.rows);
  dataRange.setBackground(colors.c50)
    .setVerticalAlignment('middle')
    .setFontColor(LITE_UI.ink);
  sheet.setRowHeights(firstDataRow, block.rows.length, LITE_DATA_ROW_HEIGHT);

  dataRanges.push([firstDataRow, block.rows.length]);

  // 4. Spacer row – deliberately left without a background.
  return firstDataRow + block.rows.length + 1;
}

/**
 * Column widths, wrapping, validation, grouping and conditional formatting.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {Sheet} sheet The Tests sheet.
 * @param {number} cols Number of columns.
 * @param {number} lastRow Last written row.
 * @param {!Array<!Array<number>>} dataRanges [firstRow, count] per block.
 */
function liteFormatTestsSheet_(ss, sheet, cols, lastRow, dataRanges) {
  for (let c = 0; c < LITE_TEST_WIDTHS.length; c++) {
    sheet.setColumnWidth(c + 1, LITE_TEST_WIDTHS[c]);
  }

  // Only row 1 is frozen, and no column is: a frozen column boundary next to
  // the merged block headers is exactly what breaks in the heavyweight build.
  sheet.setFrozenRows(1);
  sheet.setFrozenColumns(0);

  // Colored blocks provide all the structure the sheet needs, so gridlines,
  // banding and the basic filter are all left off. A basic filter in
  // particular would be actively harmful here: sorting or filtering would
  // interleave block headers with data rows and destroy the layout.
  sheet.setHiddenGridlines(true);

  // B / C / H hold prose and must wrap so the full text stays visible;
  // everything else clips so the rows keep a uniform height.
  const wrapCols = [2, 3, 8];
  const clipCols = [1, 4, 5, 6, 7];
  const bodyRows = Math.max(1, lastRow - 1);
  for (let i = 0; i < wrapCols.length; i++) {
    sheet.getRange(2, wrapCols[i], bodyRows, 1)
      .setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP)
      .setVerticalAlignment('middle');
  }
  for (let i = 0; i < clipCols.length; i++) {
    sheet.getRange(2, clipCols[i], bodyRows, 1)
      .setWrapStrategy(SpreadsheetApp.WrapStrategy.CLIP)
      .setVerticalAlignment('middle');
  }
  sheet.getRange(2, 6, bodyRows, 1).setHorizontalAlignment('center');

  // Status is a plain editable cell – no formulas, no protection.
  const statusRule = liteListValidation_(ss, 'RunStatus');
  for (let i = 0; i < dataRanges.length; i++) {
    liteApplyValidation_(
      sheet.getRange(dataRanges[i][0], LITE_STATUS_COL, dataRanges[i][1], 1), statusRule);
  }

  liteGroupBlockRows_(sheet, dataRanges);
  liteApplyTestsConditionalFormats_(sheet, cols, lastRow);
}

/**
 * Make each block's data rows collapsible.
 *
 * `shiftRowGroupDepth` throws when a group already covers the range, so every
 * call is guarded; `liteResetSheet_` has normally removed the old groups
 * already. Groups are left expanded.
 * @param {Sheet} sheet The Tests sheet.
 * @param {!Array<!Array<number>>} dataRanges [firstRow, count] per block.
 */
function liteGroupBlockRows_(sheet, dataRanges) {
  for (let i = 0; i < dataRanges.length; i++) {
    const first = dataRanges[i][0];
    const count = dataRanges[i][1];
    if (count < 1) {
      continue;
    }
    try {
      sheet.getRange(first, 1, count, 1).shiftRowGroupDepth(1);
    } catch (e) {
      // A group already exists for these rows – nothing to do.
    }
    try {
      const group = sheet.getRowGroup(first, 1);
      if (group) {
        group.expand();
      }
    } catch (e) {
      // Expanding is cosmetic; never fail the build over it.
    }
  }
}

/**
 * Status-driven conditional formatting over the whole data area.
 *
 * These backgrounds intentionally layer on top of the pale per-block colors:
 * once a test has a result, the status wins.
 * @param {Sheet} sheet The Tests sheet.
 * @param {number} cols Number of columns.
 * @param {number} lastRow Last written row.
 */
function liteApplyTestsConditionalFormats_(sheet, cols, lastRow) {
  const end = Math.max(2, lastRow);
  const all = sheet.getRange('A2:' + liteColLetter_(cols) + end);
  const priority = sheet.getRange('F2:F' + end);

  sheet.setConditionalFormatRules([
    liteFormulaRule_(all, '=$G2="Pass"', LITE_UI.passBg, null, false),
    liteFormulaRule_(all, '=$G2="Fail"', LITE_UI.failBg, LITE_UI.failText, true),
    liteFormulaRule_(all, '=$G2="Blocked"', LITE_UI.blockedBg, null, false),
    liteFormulaRule_(all, '=$G2="Skipped"', null, LITE_UI.muted, false),
    liteFormulaRule_(all, '=$G2="N-A"', null, LITE_UI.muted, false),
    liteFormulaRule_(priority, '=$F2="P0"', null, LITE_UI.failText, true)
  ]);
}

/* ------------------------------------------------------------------ */
/* 📋 Overview                                                         */
/* ------------------------------------------------------------------ */

/**
 * KPI box definitions: [label, status matched by COUNTIF, accent color].
 * A null status means the box is computed differently (Total / % Done).
 */
const LITE_KPIS = [
  ['Total', null, LITE_UI.dark],
  ['Pass', 'Pass', LITE_UI.green],
  ['Fail', 'Fail', LITE_UI.failText],
  ['Blocked', 'Blocked', LITE_UI.amber],
  ['Not Run', 'Not Run', LITE_UI.muted],
  ['% Done', null, '#1976D2']
];

/**
 * Rebuild the compact single-screen 📋 Overview sheet.
 * @param {Spreadsheet} ss The spreadsheet.
 * @param {number} totalTests Number of tests written to 🧪 Tests.
 * @return {Sheet} The Overview sheet.
 */
function liteBuildOverviewSheet_(ss, totalTests) {
  const sheet = liteResetSheet_(ss, LITE_SHEETS.OVERVIEW);
  liteEnsureSize_(sheet, 40, 12);

  // Row 1 – title.
  const title = sheet.getRange(1, 1, 1, 12);
  title.merge();
  title.setValue('  📋 Connectus Test Plan — Overview');
  title.setBackground(LITE_UI.darker)
    .setFontColor(LITE_UI.white)
    .setFontWeight('bold')
    .setFontSize(18)
    .setVerticalAlignment('middle');
  sheet.setRowHeight(1, 40);

  liteWriteKpiStrip_(sheet, 3, totalTests);
  const tableEnd = liteWriteTicketTable_(sheet, 7);
  liteWriteLegend_(sheet, tableEnd + 2);

  sheet.setHiddenGridlines(true);
  sheet.setColumnWidth(1, 120);
  sheet.setColumnWidth(2, 120);
  for (let c = 3; c <= 12; c++) {
    sheet.setColumnWidth(c, 108);
  }
  return sheet;
}

/**
 * Render the six KPI boxes as 2-row × 2-column merged tiles.
 *
 * Counting note: the Status column of 🧪 Tests holds a value only on real test
 * rows (block headers are merged and empty there, column-header rows hold the
 * literal word "Status"), so COUNTIF over $G:$G would be off by the number of
 * blocks. Rather than depend on that, `Total` is written as the static count
 * computed at build time – it is exact, cannot drift as long as the sheet is
 * rebuilt from `data.gs`, and keeps the remaining formulas trivial COUNTIFs.
 * @param {Sheet} sheet The Overview sheet.
 * @param {number} startRow Row of the big numbers.
 * @param {number} totalTests Static test count.
 */
function liteWriteKpiStrip_(sheet, startRow, totalTests) {
  const tests = liteRef_(LITE_SHEETS.TESTS);
  const statusRange = tests + '$G$2:$G';

  for (let i = 0; i < LITE_KPIS.length; i++) {
    const kpi = LITE_KPIS[i];
    const col = 1 + i * 2;

    const valueCell = sheet.getRange(startRow, col, 1, 2);
    valueCell.merge();
    if (kpi[0] === 'Total') {
      valueCell.setValue(totalTests);
    } else if (kpi[0] === '% Done') {
      // Everything that is not "Not Run" counts as touched.
      valueCell.setFormula(
        '=IFERROR((COUNTIF(' + statusRange + ',"Pass")+COUNTIF(' + statusRange + ',"Fail")+' +
        'COUNTIF(' + statusRange + ',"Blocked")+COUNTIF(' + statusRange + ',"Skipped")+' +
        'COUNTIF(' + statusRange + ',"N-A"))/' + totalTests + ',0)');
      valueCell.setNumberFormat('0%');
    } else {
      valueCell.setFormula('=COUNTIF(' + statusRange + ',"' + kpi[1] + '")');
    }
    valueCell.setFontSize(24)
      .setFontWeight('bold')
      .setFontColor(kpi[2])
      .setBackground(LITE_UI.grey)
      .setHorizontalAlignment('center')
      .setVerticalAlignment('middle');

    const labelCell = sheet.getRange(startRow + 1, col, 1, 2);
    labelCell.merge();
    labelCell.setValue(kpi[0]);
    labelCell.setFontSize(10)
      .setFontWeight('bold')
      .setFontColor(LITE_UI.dark)
      .setBackground(LITE_UI.grey)
      .setHorizontalAlignment('center')
      .setVerticalAlignment('middle');
  }

  sheet.setRowHeight(startRow, 44);
  sheet.setRowHeight(startRow + 1, 20);
  sheet.setRowHeight(startRow + 2, 12);
}

/**
 * Per-ticket progress table.
 *
 * 🧪 Tests has no Ticket column, so every count is derived from the test-ID
 * prefix (CIAC-17084 owns both `DP-` and `CMN-`, hence the SUM of two
 * COUNTIFS). The prefix map is computed from `data.gs` at build time.
 * @param {Sheet} sheet The Overview sheet.
 * @param {number} startRow Row of the table header.
 * @return {number} Last row used by the table.
 */
function liteWriteTicketTable_(sheet, startRow) {
  const tests = liteRef_(LITE_SHEETS.TESTS);
  const idRange = tests + '$A$2:$A';
  const statusRange = tests + '$G$2:$G';
  const prefixes = liteTicketPrefixes_();
  const headers = ['Ticket', 'Total', 'Pass', 'Fail', 'Blocked', 'Not Run', '% Done', 'Progress'];

  sheet.getRange(startRow, 1, 1, headers.length).setValues([headers]);
  sheet.getRange(startRow, 1, 1, headers.length)
    .setFontWeight('bold')
    .setFontColor(LITE_UI.white)
    .setBackground(LITE_UI.dark)
    .setHorizontalAlignment('center')
    .setVerticalAlignment('middle');
  sheet.setRowHeight(startRow, 24);

  const tickets = CONFIG_LISTS.Ticket;
  const labels = [];
  const formulas = [];

  for (let i = 0; i < tickets.length; i++) {
    const ticket = tickets[i];
    const row = startRow + 1 + i;
    const list = prefixes[ticket] || [];

    labels.push([ticket]);
    formulas.push([
      liteCountByPrefix_(idRange, list, statusRange, null),
      liteCountByPrefix_(idRange, list, statusRange, 'Pass'),
      liteCountByPrefix_(idRange, list, statusRange, 'Fail'),
      liteCountByPrefix_(idRange, list, statusRange, 'Blocked'),
      liteCountByPrefix_(idRange, list, statusRange, 'Not Run'),
      '=IFERROR(($C' + row + '+$D' + row + '+$E' + row + ')/$B' + row + ',0)',
      '=SPARKLINE($G' + row + ',{"charttype","bar";"max",1;"color1","#2E7D32"})'
    ]);
  }

  if (labels.length) {
    sheet.getRange(startRow + 1, 1, labels.length, 1).setValues(labels);
    sheet.getRange(startRow + 1, 1, labels.length, 1).setFontWeight('bold');
    sheet.getRange(startRow + 1, 2, formulas.length, formulas[0].length).setFormulas(formulas);
    sheet.getRange(startRow + 1, 2, formulas.length, 5).setHorizontalAlignment('center');
    sheet.getRange(startRow + 1, 7, formulas.length, 1).setNumberFormat('0%');
    sheet.getRange(startRow + 1, 1, formulas.length, headers.length)
      .setBorder(true, true, true, true, true, true, LITE_UI.line,
        SpreadsheetApp.BorderStyle.SOLID);
  }

  return startRow + tickets.length;
}

/**
 * Build a `SUM(COUNTIFS(...))` expression counting the tests of one ticket.
 * @param {string} idRange A1 range of the ID column on 🧪 Tests.
 * @param {!Array<string>} prefixes ID prefixes owned by the ticket.
 * @param {string} statusRange A1 range of the Status column on 🧪 Tests.
 * @param {?string} status Status to match, or null to count every test.
 * @return {string} The formula.
 */
function liteCountByPrefix_(idRange, prefixes, statusRange, status) {
  if (!prefixes.length) {
    return '=0';
  }
  const terms = prefixes.map(function (prefix) {
    const idTerm = idRange + ',"' + prefix + '-*"';
    return status
      ? 'COUNTIFS(' + idTerm + ',' + statusRange + ',"' + status + '")'
      : 'COUNTIFS(' + idTerm + ')';
  });
  return '=SUM(' + terms.join(',') + ')';
}

/**
 * Status legend plus one row per ticket color family.
 * @param {Sheet} sheet The Overview sheet.
 * @param {number} startRow Row of the legend title.
 * @return {number} Last row used.
 */
function liteWriteLegend_(sheet, startRow) {
  sheet.getRange(startRow, 1).setValue('Legend');
  sheet.getRange(startRow, 1, 1, 4)
    .merge()
    .setFontWeight('bold')
    .setFontColor(LITE_UI.white)
    .setBackground(LITE_UI.dark)
    .setVerticalAlignment('middle');

  const statuses = [
    ['Pass', 'Test passed', LITE_UI.passBg, LITE_UI.ink],
    ['Fail', 'Test failed – needs a bug', LITE_UI.failBg, LITE_UI.failText],
    ['Blocked', 'Cannot run yet (setup / dependency)', LITE_UI.blockedBg, LITE_UI.ink],
    ['Skipped / N-A', 'Intentionally not executed', LITE_UI.white, LITE_UI.muted],
    ['Not Run', 'Default state', LITE_UI.white, LITE_UI.ink]
  ];

  let row = startRow + 1;
  for (let i = 0; i < statuses.length; i++) {
    sheet.getRange(row, 1).setValue(statuses[i][0])
      .setBackground(statuses[i][2])
      .setFontColor(statuses[i][3])
      .setFontWeight('bold');
    sheet.getRange(row, 2, 1, 3).merge().setValue(statuses[i][1]);
    row++;
  }

  row++;
  sheet.getRange(row, 1).setValue('Block colors');
  sheet.getRange(row, 1, 1, 4)
    .merge()
    .setFontWeight('bold')
    .setFontColor(LITE_UI.white)
    .setBackground(LITE_UI.dark)
    .setVerticalAlignment('middle');
  row++;

  // One row per color family actually used by a block, in render order.
  const blocks = liteDeriveBlocks_();
  const seen = {};
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const groupKey = LITE_FAMILY_BY_KEY.hasOwnProperty(block.feature) ? block.feature : block.ticket;
    if (seen[groupKey]) {
      continue;
    }
    seen[groupKey] = true;
    const family = LITE_COLORS[block.familyIndex];
    sheet.getRange(row, 1).setValue(family.emoji + ' ' + family.name)
      .setBackground(family.c100)
      .setFontWeight('bold');
    sheet.getRange(row, 2, 1, 3).merge().setValue(groupKey);
    row++;
  }

  return row - 1;
}

/* ------------------------------------------------------------------ */
/* 🧱 Setup                                                            */
/* ------------------------------------------------------------------ */

/** Headers of the flat 🧱 Setup table. */
const LITE_SETUP_HEADERS = ['Setup ID', 'Title', 'Type', 'Description', 'Depends On', 'Status'];

/** Column widths of the 🧱 Setup table. */
const LITE_SETUP_WIDTHS = [110, 300, 110, 560, 120, 120];

/** Indices into a SETUPS row. */
const LITE_SETUP_SRC = {
  ID: 0,
  TITLE: 1,
  TYPE: 2,
  DESCRIPTION: 3,
  DEPLOYMENT: 4,
  DEPENDS_ON: 5,
  STATUS: 7
};

/**
 * Rebuild the 🧱 Setup sheet as a simple flat six-column table.
 *
 * `Deployment Config` and `Build/Bucket` are dropped from the grid; the
 * deployment note is folded into the description so nothing is lost.
 * @param {Spreadsheet} ss The spreadsheet.
 * @return {Sheet} The Setup sheet.
 */
function liteBuildSetupSheet_(ss) {
  const sheet = liteResetSheet_(ss, LITE_SHEETS.SETUP);
  const cols = LITE_SETUP_HEADERS.length;
  liteEnsureSize_(sheet, SETUPS.length + 5, cols);

  sheet.getRange(1, 1, 1, cols).setValues([LITE_SETUP_HEADERS]);
  sheet.getRange(1, 1, 1, cols)
    .setFontWeight('bold')
    .setFontColor(LITE_UI.white)
    .setBackground(LITE_UI.dark)
    .setHorizontalAlignment('center')
    .setVerticalAlignment('middle');
  sheet.setRowHeight(1, 26);

  const rows = SETUPS.map(function (src) {
    const deployment = String(src[LITE_SETUP_SRC.DEPLOYMENT] || '').trim();
    let description = String(src[LITE_SETUP_SRC.DESCRIPTION] || '').trim();
    if (deployment && deployment !== 'None') {
      description += '\nDeployment: ' + deployment;
    }
    return [
      src[LITE_SETUP_SRC.ID],
      src[LITE_SETUP_SRC.TITLE],
      src[LITE_SETUP_SRC.TYPE],
      description,
      src[LITE_SETUP_SRC.DEPENDS_ON],
      src[LITE_SETUP_SRC.STATUS]
    ];
  });

  if (rows.length) {
    const body = sheet.getRange(2, 1, rows.length, cols);
    body.setValues(rows);
    body.setVerticalAlignment('middle');
    sheet.getRange(2, 4, rows.length, 1).setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP);
    sheet.getRange(2, 2, rows.length, 1).setWrapStrategy(SpreadsheetApp.WrapStrategy.WRAP);
    sheet.getRange(2, 1, rows.length, 1).setFontWeight('bold');

    liteApplyValidation_(sheet.getRange(2, 3, rows.length, 1), liteListValidation_(ss, 'SetupType'));
    liteApplyValidation_(sheet.getRange(2, 6, rows.length, 1), liteListValidation_(ss, 'SetupStatus'));

    sheet.setConditionalFormatRules([
      liteFormulaRule_(body, '=$F2="Done"', LITE_UI.passBg, LITE_UI.green, true),
      liteFormulaRule_(body, '=$F2="Failed"', LITE_UI.failBg, LITE_UI.failText, true),
      liteFormulaRule_(body, '=$F2="In Progress"', LITE_UI.blockedBg, null, false),
      liteFormulaRule_(body, '=$F2="Pending"', null, LITE_UI.muted, false)
    ]);
  }

  for (let c = 0; c < LITE_SETUP_WIDTHS.length; c++) {
    sheet.setColumnWidth(c + 1, LITE_SETUP_WIDTHS[c]);
  }
  sheet.setFrozenRows(1);
  sheet.setFrozenColumns(0);
  sheet.setHiddenGridlines(true);
  return sheet;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

/**
 * Build (or rebuild) the lite workbook.
 *
 * Idempotent: every sheet is wiped in place (never deleted, so cross-sheet
 * references never turn into #REF!) and re-rendered, so running this twice in
 * a row is safe. Sheets belonging to the heavyweight `build.gs` build, if any
 * exist in the same spreadsheet, are left completely untouched.
 */
function buildLiteWorkbook() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  // Create every tab up front so cross-sheet formulas always resolve.
  for (let i = 0; i < LITE_SHEET_ORDER.length; i++) {
    liteGetOrCreateSheet_(ss, LITE_SHEET_ORDER[i]);
  }

  liteBuildConfigSheet_(ss);
  const tests = liteBuildTestsSheet_(ss);
  liteBuildSetupSheet_(ss);
  liteBuildOverviewSheet_(ss, TEST_CASES.length);

  liteOrderSheets_(ss);

  // The menu is installed here too, so it appears even when this file's
  // `liteOnOpen()` is not wired up as the project's onOpen trigger.
  liteInstallMenu_();

  ss.toast('Lite workbook rebuilt: ' + TEST_CASES.length + ' tests on ' +
    tests.getName() + '.', '🧪 Test Plan (Lite)', 5);
}

/* ------------------------------------------------------------------ */
/* Custom menu                                                         */
/* ------------------------------------------------------------------ */

/**
 * Install the "🧪 Test Plan (Lite)" menu.
 * Kept separate from the trigger so `buildLiteWorkbook()` can call it too.
 */
function liteInstallMenu_() {
  try {
    SpreadsheetApp.getUi()
      .createMenu('🧪 Test Plan (Lite)')
      .addItem('🏗️ Rebuild', 'buildLiteWorkbook')
      .addItem('🔄 Reset Statuses', 'liteResetStatuses')
      .addToUi();
  } catch (e) {
    // No UI context (e.g. running from a trigger or the API) – ignore.
  }
}

/**
 * Open-trigger entry point for this builder.
 *
 * Deliberately NOT named `onOpen`: an Apps Script project may declare that
 * function only once, and `build.gs` already does. See the file header for
 * the two supported ways of wiring this up.
 */
function liteOnOpen() {
  liteInstallMenu_();
}

/* ------------------------------------------------------------------ */
/* Menu actions                                                        */
/* ------------------------------------------------------------------ */

/**
 * Set every non-empty Status cell on 🧪 Tests back to "Not Run",
 * after asking for confirmation.
 */
function liteResetStatuses() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(LITE_SHEETS.TESTS);
  let ui = null;
  try {
    ui = SpreadsheetApp.getUi();
  } catch (e) {
    ui = null;
  }

  if (!sheet) {
    if (ui) {
      ui.alert('Sheet "' + LITE_SHEETS.TESTS + '" not found. Run 🏗️ Rebuild first.');
    }
    return;
  }

  if (ui) {
    const answer = ui.alert(
      'Reset Statuses',
      'Set every status on ' + LITE_SHEETS.TESTS + ' back to "' + LITE_DEFAULT_STATUS + '"?\n' +
      'Notes / Evidence are kept.',
      ui.ButtonSet.YES_NO);
    if (answer !== ui.Button.YES) {
      return;
    }
  }

  const lastRow = sheet.getLastRow();
  if (lastRow < 2) {
    return;
  }

  const range = sheet.getRange(2, LITE_STATUS_COL, lastRow - 1, 1);
  const values = range.getValues();
  let reset = 0;
  for (let i = 0; i < values.length; i++) {
    const value = String(values[i][0]).trim();
    // Column-header rows carry the literal word "Status" and must survive.
    if (value && value !== 'Status' && value !== LITE_DEFAULT_STATUS) {
      values[i][0] = LITE_DEFAULT_STATUS;
      reset++;
    }
  }
  if (reset) {
    range.setValues(values);
  }
  ss.toast('Reset ' + reset + ' status cell(s).', '🧪 Test Plan (Lite)', 5);
}
