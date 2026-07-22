function isIntegrationAvailable(brandName, allInstances) {
    const brandInstances = Object.keys(allInstances).filter(
        instanceName => 
        allInstances[instanceName].brand.toLowerCase() === brandName.toLowerCase() &&
        allInstances[instanceName].state === 'active'
    );
  
    const readableOutput = brandInstances.length > 0 ? 'yes' : 'no';

    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': readableOutput,
        'HumanReadable': readableOutput,
        'EntryContext': {'brandInstances': brandInstances}
    };
}


function main() {
    const brandNames = argToList(args.brandname);
    const allInstances = getModules();

    const results = [];
    for (let brandName of brandNames) {
        const result = isIntegrationAvailable(brandName, allInstances);
        results.push(result);
    }

    return results;
}


try {
    return main();
} catch (error) {
    throw `Failed to execute automation. Error:\n${error}`;
}
