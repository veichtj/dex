# Contributing to dex fork

As the git workflow we are using in Kyma differs from the workflow in this repo, this readme contains instructions for some basic operations.

## Prepare a local repository:

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

> always check out from `kyma-master` branch

> make sure to choose `kyma-incubator/dex` repository and `kyma-master` branch as the base for your PR

```shell script
# fetch recent kyma-master

git checkout kyma-master
git pull origin kyma-master

# Create a branch for your changes

git checkout -b <your_branch_name>

# ... commit changes ...

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

### To update the remote master branch:

>**NOTE:** You must have permissions to push to the `master` branch to complete this operation.

If you prepared your local repository following the steps above, `git pull` command on `master` branch will fetch changes from the original repository to your local repository. To push it to remote repository simply type `git push origin master`.
