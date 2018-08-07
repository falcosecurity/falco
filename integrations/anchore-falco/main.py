import os

import actions, infrastructure


def main():
    anchore_client = infrastructure.AnchoreClient(
        os.environ.get('ANCHORE_CLI_USER', 'admin'),
        os.environ['ANCHORE_CLI_PASS'],
        os.environ.get('ANCHORE_CLI_URL', 'http://localhost:8228/v1'),
        os.environ.get('ANCHORE_CLI_SSL_VERIFY', True)
    )
    action = actions.CreateFalcoRuleFromAnchoreStopPolicyResults(anchore_client)

    result = action.run()

    print(result)


if __name__ == '__main__':
    main()
