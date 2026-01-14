def suggest_fix(entity):
    if "tls" in entity.weakness:
        return "Upgrade TLS config to TLSv1.2+"


#pending