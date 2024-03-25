def get_padded_version(version):
    if version == "-" or version == "":
        return version

    else:
        # normalizing edge cases:
        version = version.replace("\\(", ".").replace("\\)", ".").rstrip(".")

        ret_list = []

        splitted_version = version.split(".")
        # perform check if last part of version can be cast to an int
        try:
            int(splitted_version[-1])
            # can be cast to an int, proceed 'normally'
            for v in splitted_version:
                try:
                    ret_list.append(f"{int(v):05d}")
                except ValueError:
                    ret_list.append(v.rjust(5, "0"))
        except ValueError:
            # last part of the version cannot be cast to an int, so this means it's either a string or a
            # string combined with an integer; handle accordingly

            # first handle all version identifiers leading upto the last part
            if len(splitted_version) > 1:
                for i in range(len(splitted_version) - 1):
                    try:
                        ret_list.append(f"{int(splitted_version[i]):05d}")
                    except ValueError:
                        ret_list.append(splitted_version[i].rjust(5, "0"))

            # handle the last part
            # check if the last entry is smaller than 5 characters, if so just use that...
            if len(splitted_version[-1]) > 5:
                try:
                    ret_list.append(f"{int(splitted_version[-1]):05d}")
                except ValueError:
                    ret_list.append(splitted_version[-1].rjust(5, "0"))
            # check is last entry consists only of alphanumeric characters
            elif splitted_version[-1].isalpha():
                ret_list.append(splitted_version[-1].rjust(5, "0"))
            else:
                loop_i = 0
                loop_count = len(splitted_version[-1])

                # int/str combined value; handle accordingly
                while loop_i < loop_count:
                    current_i = loop_i
                    # probably digit; so check;
                    if splitted_version[-1][loop_i].isdigit():
                        try:
                            ret_list.append(
                                f"{int(splitted_version[-1][loop_i]):05d}"
                            )
                        except ValueError:
                            ret_list.append(
                                splitted_version[-1][loop_i].rjust(5, "0")
                            )
                        finally:
                            # perform check if anything that follows consists only of string characters
                            if splitted_version[-1][loop_i + 1:].isalpha():
                                ret_list.append(
                                    splitted_version[-1][loop_i + 1:].rjust(5, "0")
                                )
                                # no point proceeding; just break
                                break
                            loop_i += 1
                    else:
                        # ok so probably last part of version identifier is a string; add that with a loop
                        version_string = ""
                        try:
                            while splitted_version[-1][loop_i].isalpha():
                                version_string += splitted_version[-1][loop_i]
                                loop_i += 1
                        except IndexError:
                            # finished splitted_version variable; just pass
                            loop_i += 1
                            pass

                        ret_list.append(version_string.rjust(5, "0"))

                    if loop_i == current_i:
                        loop_i += 1

        return ".".join(ret_list)


def get_cpe_info(cpeuri: str):
    query = {}

    if "versionStartExcluding" in cpeuri:
        if "versionEndExcluding" in cpeuri:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gt": get_padded_version(cpeuri["versionStartExcluding"]),
                    "$lt": get_padded_version(cpeuri["versionEndExcluding"]),
                },
            }
        elif "versionEndIncluding" in cpeuri:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gt": get_padded_version(cpeuri["versionStartExcluding"]),
                    "$lte": get_padded_version(cpeuri["versionEndIncluding"]),
                },
            }
        else:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gt": get_padded_version(cpeuri["versionStartExcluding"])
                },
            }

    elif "versionStartIncluding" in cpeuri:
        if "versionEndExcluding" in cpeuri:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gte": get_padded_version(cpeuri["versionStartIncluding"]),
                    "$lt": get_padded_version(cpeuri["versionEndExcluding"]),
                },
            }
        elif "versionEndIncluding" in cpeuri:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gte": get_padded_version(cpeuri["versionStartIncluding"]),
                    "$lte": get_padded_version(cpeuri["versionEndIncluding"]),
                },
            }
        else:
            query = {
                "deprecated": False,
                "cpe": cpeuri["criteria"],
                "padded_version": {
                    "$gte": get_padded_version(cpeuri["versionStartIncluding"])
                },
            }

    elif "versionEndExcluding" in cpeuri:
        query = {
            "deprecated": False,
            "cpe": cpeuri["criteria"],
            "padded_version": {
                "$lt": get_padded_version(cpeuri["versionEndExcluding"])
            },
        }

    elif "versionEndIncluding" in cpeuri:
        query = {
            "deprecated": False,
            "cpe": cpeuri["criteria"],
            "padded_version": {
                "$lte": get_padded_version(cpeuri["versionEndIncluding"])
            },
        }

    return query


def get_cpe_from_query(query, db):

    return db.cpes.find(query)


def determine_cve_cpes(configs, db):
    cpes = []
    vendors = []
    products = []

    for node in configs:
        for cpe in node["nodes"]:
            if "cpeMatch" in cpe:
                for cpeuri in cpe["cpeMatch"]:
                    if "criteria" not in cpeuri:
                        continue
                    if cpeuri["vulnerable"]:
                        query = get_cpe_info(cpeuri)
                        if query != {}:
                            cpe_info = sorted(
                                get_cpe_from_query(query, db),
                                key=lambda x: x["padded_version"],
                            )
                            if cpe_info:
                                if not isinstance(cpe_info, list):
                                    cpe_info = [cpe_info]

                                for vulnerable_version in cpe_info:
                                    cpe = vulnerable_version['cpe']
                                    vendor = vulnerable_version['vendor']
                                    product = vulnerable_version['product']
                                    if cpe not in cpes:
                                        cpes.append(cpe)
                                    if vendor not in vendors:
                                        vendors.append(vendor)
                                    if product not in products:
                                        products.append(product)

    return cpes, vendors, products
