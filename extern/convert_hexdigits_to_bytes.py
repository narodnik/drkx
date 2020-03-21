import itertools
import sys

def main(argv):
    if len(argv) != 2:
        print("wrong args")
        return

    v = sys.argv[1]
    v = v.split(" ")

    s = None

    for x, i in zip(v, itertools.cycle(range(8))):
        if s is None:
            s = ""
        elif i == 0:
            s += ",\n"
        else:
            s += ", "

        s += "0x%s" % x

    print(s)

if __name__ == "__main__":
    sys.exit(main(sys.argv))

