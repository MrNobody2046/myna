import core
import utils

def build_action_from_raw_request(filename):
    with open(filename) as raw:
        bf = raw.read()
        ac = core.ActionBuilder(request=bf)

def search_actions():
    pass


if __name__ == "__main__":
    ac = core.ActionBuilder()
    print ac._action_string
