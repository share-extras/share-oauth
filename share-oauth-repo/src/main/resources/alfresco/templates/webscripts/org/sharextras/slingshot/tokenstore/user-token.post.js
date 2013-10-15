function main()
{
    jsonStr = "{}";
    if (person.hasAspect("se:userTokens"))
    {
        person.addAspect("se:userTokens");
    }
    var children = person.childAssocs["se:tokenContent"],
        contentNode;
    if (children == null || children.length == 0)
    {
        contentNode = person.createNode("userTokens", "cm:content", "se:tokenContent");
        contentNode.content = "{}";
        contentNode.setInheritsPermissions(false);
    }
    else
    {
        contentNode = children[0];
    }
    var jsonObj = jsonUtils.toObject(contentNode.content);

    // JSON should be in a tree-like structure, e.g. { org { sharextras: { ... } } }
    // Base path from URL args should be something like org/sharextras/blah (default otherwise is to return everything)
    var basePath = url.templateArgs.path || "",
        baseParts = basePath.split("/"),
        baseObj = jsonObj;
    
    for (var i = 0; i < baseParts.length; i++)
    {
        if (baseParts[i] != "") // Skip empty parts
        {
            baseObj = baseObj[baseParts[i]] || (baseObj[baseParts[i]] = {});
        }
    }
    
    // Get object from the request body
    var jsonData = jsonUtils.toObject(requestbody.content);
    
    // Set contents of base object to jsonData
    // jsonData should be MERGED into baseObj
    mergeObjects(baseObj, jsonData);
    
    // Save the complete object back to the file
    contentNode.content = jsonUtils.toJSONString(jsonObj);
    
    jsonStr = jsonUtils.toJSONString(baseObj);
        model.jsonStr = jsonStr;
}
/**
 * Copy object 2 into object 1
 * @param obj1
 * @param obj2
 * @returns
 */
function mergeObjects(obj1, obj2)
{
    if (typeof obj1 != typeof obj2)
    {
        throw "Objects " + obj1 + " and " + obj2 + " are not of same type";
    }
    for (p in obj2)
    {
        if (typeof obj1[p] == "object" && typeof obj2[p] == "object")
        {
            mergeObjects(obj1[p], obj2[p]);
        }
        else if (typeof obj1[p] != "undefined" && typeof obj2[p] == "undefined")
        {
            // Do nothing, no replacement specified
        }
        else if (typeof obj1[p] == "undefined" && typeof obj2[p] != "undefined")
        {
            obj1[p] = obj2[p];
        }
        else 
        {
            // Both non-objects
            obj1[p] = obj2[p];
        }
    }
    return obj1;
}
main();