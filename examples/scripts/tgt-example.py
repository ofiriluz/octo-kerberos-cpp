from octo_krb5 import KRB5Authenticator, KRB5UserCredentials, DEFAULT_KERBEROS_PORT
import argparse
import pprint


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=DEFAULT_KERBEROS_PORT)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--service", required=True)
    args = parser.parse_args()

    creds = KRB5UserCredentials(args.username, args.password)
    auth = KRB5Authenticator(args.realm, args.host if args.host else args.realm, args.port)
    auth.initialize_authenticator()
    tgt = auth.generate_tgt(creds)

    serialized_tgt = tgt.serialize()
    pprint.pprint(serialized_tgt)
    tgt = auth.deserialize_tgt(serialized_tgt)
    pprint.pprint(tgt.serialize())

    st = auth.generate_service_ticket(tgt, args.service)

    serialized_st = st.serialize()
    pprint.pprint(serialized_st)
    st = auth.deserialize_service_ticket(serialized_st)
    pprint.pprint(st.serialize())


if __name__ == "__main__":
    main()
