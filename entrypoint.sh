#!/usr/bin/env bash

echo "Environment Variables:"
echo "   Workflow:   $GITHUB_WORKFLOW"
echo "   Action:     $GITHUB_ACTION"
echo "   Actor:      $GITHUB_ACTOR"
echo "   Repository: $GITHUB_REPOSITORY"
echo "   Event-name: $GITHUB_EVENT_NAME"
echo "   Event-path: $GITHUB_EVENT_PATH"
echo "   Workspace:  $GITHUB_WORKSPACE"
echo "   SHA:        $GITHUB_SHA"
echo "   REF:        $GITHUB_REF"
echo "   HEAD-REF:   $GITHUB_HEAD_REF"
echo "   BASE-REF:   $GITHUB_BASE_REF"
echo "   PWD:        $(pwd)"

SRC_PATH=$GITHUB_WORKSPACE/$1
BLUEZ_PATH=$GITHUB_WORKSPACE/$2

echo "Input Parameters"
echo "   Source Path: $SRC_PATH"
echo "   Bluez Path: $BLUEZ_PATH"

if [ -z "$GITHUB_TOKEN" ]; then
	echo "Set GITHUB_TOKEN environment variable"
	exit 1
fi

# Get PR number from GITHUB_REF (refs/pull/#/merge)
PR=${GITHUB_REF#"refs/pull/"}
PR=${PR%"/merge"}

# Make Result directory
mkdir results

/run-ci.py -c /config.ini -p $PR -r $GITHUB_REPOSITORY -s $SRC_PATH -b $BLUEZ_PATH -v

# Save the test-runner results
tar -cvzf results.tar.gz results
