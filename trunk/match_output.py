import re, sys

def Main():
  if len(sys.argv) == 2:
    verbose = False
  elif len(sys.argv) == 3 and sys.argv[2].lower() == "--verbose":
    verbose = True
  else:
    print >>sys.stderr, "A regular expression to match stdin to must be given"
    return 1
  try:
    regexp = re.compile(sys.argv[1])
  except re.error, e:
    print >>sys.stderr, "The regular expression cannot be compiled:"
    print >>sys.stderr, "  Error: %s" % e
    return 1
  stdin_data = sys.stdin.read();
  if re.match(regexp, stdin_data):
    if (verbose): print "OK"
    return 0
  if (verbose):
    print >>sys.stderr, repr(regexp.pattern)
    print >>sys.stderr, repr(stdin_data)
  return 1

if __name__ == "__main__":
  exit(Main())