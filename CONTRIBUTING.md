# Contribution - Dex fork for Kyma

This readme describes the workflow for basic operations required to contribute to this fork, which is different from the Kyma-flavored Git workflow.  

## Prepare a local repository

```shell script
# Clone the fork repository

cd $GOPATH/src/github.com
mkdir dexidp
cd dexidp
git clone https://github.com/kyma-incubator/dex.git
cd dex

# Configure the cloned repository

git remote add upstream https://github.com/dexidp/dex.git
git fetch upstream
git branch -u upstream/master
```

## Create a pull request

>**NOTE:** Always check out from the `kyma-master` branch. Chose the `kyma-incubator/dex` repository and the `kyma-master` branch as the base of your PR.

```shell script
# Fetch kyma-master

git checkout kyma-master
git pull origin kyma-master

# Create a branch for your changes

git checkout -b <your_branch_name>

# Commit changes to your branch

# Push your branch

git push origin <your_branch_name>

# Create a PR through the GitHub UI
```

## Update the kyma-master branch

Update of `kyma-master` branch is mostly based on creating a PR to the fork. The change is that you should update the `master` branch before:

```shell script
# fetch changes from the original repository

git checkout master
git pull
```

Then in the place of `# ... commit changes ...` comment, you should merge the `master` to your branch. You have to resolve the conflicts if there are any.

```shell script
# merge changes from master to your branch

git merge master
```

## Update the remote master branch

>**NOTE:** You must have permissions to push to the `master` branch to complete this operation.

If you prepared your local repository following the steps above, `git pull` command on `master` branch will fetch changes from the original repository to your local repository. To push it to remote repository simply type `git push origin master`.
