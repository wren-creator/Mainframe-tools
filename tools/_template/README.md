# <tool-name>

**Target:** RACF / z/OS | Linux on Z | z/VM | Network
**Language:** Python | Shell | Go

## What it audits

One paragraph. What artifact does it read, what questions does it answer.

## Input

What you feed it and how to produce that on the source system. Example:

```
# On z/OS, unload the RACF database:
//UNLOAD   EXEC PGM=IRRDBU00,PARM=NOLOCKINPUT
```

Never commit real unloads or extracts. Put sanitized examples in `samples/`.

## Running it

```
./run.sh path/to/input
```

## Output

What the report looks like and how to read a finding. Include severity meanings.

## Checks performed

- [ ] check one
- [ ] check two

## Tests

```
pytest        # or: ./test.sh
```
