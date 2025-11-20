/**
 * Creates an HTML email body by replacing placeholders with actual values
 * Supports different Cortex marketplaces: XSOAR, XSIAM, and unified platform
 */

// Constants
const MARKETPLACES = {
    XSOAR: 'xsoar',
    XSIAM: 'x2',
    PLATFORM: 'unified_platform'
};

const ENTITY_TYPES = {
    INCIDENT: 'incident',
    ALERT: 'alert',
    ISSUE: 'issue',
    OBJECT: 'object'
};

/**
 * Safe string replacement utility
 * @param {string} text - Original text
 * @param {string} search - Text to search for
 * @param {string} replacement - Replacement text
 * @returns {string} Text with all occurrences replaced
 */
function replaceAll(text, search, replacement) {
    if (!text || typeof text !== 'string') return text;
    return text.split(search).join(replacement || '');
}

/**
 * Get a specific label from incident/alert/issue labels
 * @param {Object} entity - The incident, alert, or issue object
 * @param {string} path - The label path (e.g., 'incident.labels.labelName')
 * @returns {string|null} Label value or null if not found
 */
function getLabel(entity, path) {
    try {
        const pathParts = path.split('.');
        const labelName = pathParts[2];

        for (let i = 0; i < entity.labels.length; i++) {
            if (entity.labels[i] && entity.labels[i].type === labelName) {
                return entity.labels[i].value || null;
            }
        }
    } catch (error) {
        logDebug("Error getting label: " + error.message);
    }
    return null;
}

/**
 * Get the appropriate entity type based on marketplace
 * @param {string} marketplace - Current marketplace
 * @returns {string} Entity type name
 */
function getEntityType(marketplace) {
    switch (marketplace) {
        case MARKETPLACES.XSIAM:
            return ENTITY_TYPES.ALERT;
        case MARKETPLACES.PLATFORM:
            return ENTITY_TYPES.ISSUE;
        default:
            return ENTITY_TYPES.INCIDENT;
    }
}

/**
 * Process field path and extract value
 * @param {string} path - Field path
 * @param {string} marketplace - Current marketplace
 * @param {Object} entity - Current entity (incident/alert/issue)
 * @param {Object} objectArg - Optional object argument
 * @returns {*} Field value or null
 */
function processFieldPath(path, marketplace, entity, objectArg) {
    try {
        const entityType = getEntityType(marketplace);
        
        // Handle labels
        if (path.indexOf(entityType + '.labels.') === 0) {
            logDebug("Field " + path + " is handled as label.");
            return getLabel(entity, path);
        }
        
        // Handle entity fields
        if (path.indexOf(entityType + '.') === 0) {
            const entityWrapper = {};
            entityWrapper[entityType] = entity;
            let value = dq(entityWrapper, path);
            
            // Try custom fields if direct field lookup fails
            if (value === null) {
                logDebug("Field " + path + " not found directly. Trying custom fields.");
                const customFieldPath = path.replace(entityType + '.', entityType + '.CustomFields.');
                value = dq(entityWrapper, customFieldPath);
            }
            return value;
        }
        
        // Handle object fields
        if (path.indexOf('object.') === 0) {
            logDebug("Field " + path + " is part of object.");
            if (!objectArg) {
                logDebug("No object provided for object field");
                return null;
            }
            
            const obj = (typeof objectArg === 'string') ? JSON.parse(objectArg) : objectArg;
            return dq({'object': obj}, path);
        }
        
        // Handle investigation context
        return dq(invContext, path);
        
    } catch (error) {
        logDebug("Error processing field path " + path + ": " + error.message);
        return null;
    }
}

// Main execution
try {    
    // Get template content
    const res = executeCommand("getList", {"listName": args.listTemplate});
    
    if (!res || !res[0]) {
        return {
            Type: entryTypes.error,
            Contents: "Failed to retrieve template list"
        };
    }
    
    if (res[0].Type === entryTypes.error) {
        return res;
    }
    
    // Get marketplace information
    const cortexMarketplacesDetail = getDemistoVersion().platform;
    logDebug("Marketplace: " + cortexMarketplacesDetail);
    
    // Find and process placeholders
    let html = res[0].Contents || '';
    const placeholderRegex = /\${(.+?)}/g;
    const fieldMap = {};
    let match;
    
    // Reset regex lastIndex to ensure we catch all matches
    placeholderRegex.lastIndex = 0;
    
    while ((match = placeholderRegex.exec(html)) !== null) {
        const path = match[1];
        if (!fieldMap.hasOwnProperty(path)) { // Avoid processing the same path multiple times
            fieldMap[path] = processFieldPath(path, cortexMarketplacesDetail, incidents[0], args.object);
            logDebug("Field value fetched for " + path + ": " + fieldMap[path]);
        }
    }
    
    // Replace placeholders with actual values
    for (const path in fieldMap) {
        const value = fieldMap[path];
        const placeholder = '${' + path + '}';
        
        if (value !== null && value !== undefined) {
            logDebug("Replacing placeholder " + placeholder + " with: " + value);
            html = replaceAll(html, placeholder, String(value));
        } else if (args.removeNotFound === 'yes') {
            logDebug("Removing unfound placeholder: " + placeholder);
            html = replaceAll(html, placeholder, '');
        } else {
            logDebug("Leaving placeholder unchanged: " + placeholder);
        }
    }
    
    // Set context and return result
    setContext(args.key, html);
    
    return {
        ContentsFormat: formats.json,
        Type: entryTypes.note,
        Contents: {htmlBody: html},
        HumanReadable: 'HTML body set to context key "' + args.key + '"'
    };
    
} catch (error) {
    logDebug("Script execution error: " + error.message);
    return {
        Type: entryTypes.error,
        Contents: "Script execution failed: " + error.message
    };
}
