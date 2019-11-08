# Contributing to dex fork

As the git workflow we are using in Kyma differs from the workflow in this repo, this readme contains instructions for some basic operations.

## To prepare a local repository:

```shell script
# clone fork's repository

cd $GOPATH/src/github.com
mkdir dexidp
cd dexidp
git clone https://github.com/kyma-incubator/dex.git
cd dex

# configure the repository

git remote add upstream https://github.com/dexidp/dex.git
git fetch upstream
git branch -u upstream/master
```

## To create a PR to the fork:

> always check out from `kyma-master` branch

> make sure to choose `kyma-incubator/dex` repository and `kyma-master` branch as the base for your PR

```shell script
# fetch recent kyma-master

git checkout kyma-master
git pull origin kyma-master

# create your branch with changes

git checkout -b <your_branch_name>

# ... commit changes ...

# push your branch

git push origin <your_branch_name>

# create a PR from the browser
```

## To update kyma-master branch:

Update of `kyma-master` branch is mostly based on creating a PR to the fork. The change is that you should update the `master` branch before:

```shell script
# fetch changes from original repository

git checkout master
git pull
```

Then in the place of `# ... commit changes ...` comment, you should merge the `master` to your branch. You have to resolve the conflicts if there are any.

```shell script
# merge changes from master to your branch

git merge master
```

### To update remote master branch:

> you have to be able to push to `master` branch to complete this operation

If you prepared your local repository following the steps above, `git pull` command on `master` branch will fetch changes from original repository to your local repository. To push it to remote repository simply type `git push origin master`.