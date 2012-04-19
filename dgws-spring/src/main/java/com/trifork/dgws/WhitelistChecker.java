package com.trifork.dgws;

import java.util.Set;

public interface WhitelistChecker {
    Set<String> getWhitelist(String whitelist);
}
