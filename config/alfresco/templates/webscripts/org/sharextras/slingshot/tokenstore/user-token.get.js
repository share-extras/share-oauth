function main()
{
    jsonStr = "{}";
    if (person.hasAspect("se:userTokens"))
    {
        var children = person.childAssocs["se:tokenContent"];
        if (children.length == 1)
        {
            var tokenContent = children[0].content,
                json = jsonUtils.toObject(tokenContent);
            
            // JSON should be in a tree-like structure, e.g. { org { sharextras: { ... } } }
            // Base object from URL args should be something like org/sharextras/blah (default otherwise is to return everything)
            var basePath = url.templateArgs.path || "",
                baseParts = basePath.split("/"),
                baseObj = json;
            
            for (var i = 0; i < baseParts.length; i++)
            {
                if (baseParts[i] != "")
                {
                    baseObj = baseObj[baseParts[i]];
                }
            }
            
            // Apply any filter
            var filteredObj = {}, currFilteredObj = filteredObj, currObj = baseObj, filterParts = (args.filter || "").split("."), part, lastPart;
            filteredObj = findValueByDotNotation(baseObj, args.filter || "", {});
            
            jsonStr = jsonUtils.toJSONString(filteredObj);
        }
    }
    model.jsonStr = jsonStr;
}
function findValueByDotNotation(obj, propertyPath, defaultValue)
{
    var value = defaultValue ? defaultValue : null;
    if (propertyPath && obj)
    {
        var currObj = obj;
        var newObj = {}, ptrObj = newObj;
        var props = propertyPath.split(".");
        for (var i = 0; i < props.length; i++)
        {
            currObj = currObj[props[i]];
            ptrObj[props[i]] = (typeof currObj == "object") ? {} : currObj;
            ptrObj = ptrObj[props[i]];
            if (typeof currObj == "undefined")
            {
                return value;
            }
        }
        return newObj;
    }
    return value;
};
main();