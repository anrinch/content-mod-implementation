#include "DynamicBlockList.hpp"
#include <memory>
#include <vector>

namespace dynamicblocklist {

BlockListNode::BlockListNode(int start, int finish, ZZ_p value,
                             std::weak_ptr<BlockListTree> treeptr,
                             std::weak_ptr<BlockListNode> parentptr) {
  this->value = value;
  this->tree = treeptr;
  this->parent = parentptr;
  this->start = start;
  this->finish = finish;
  this->leaf = false;
  this->leftchild = nullptr;
  this->rightchild = nullptr;

  // this is the condition for a leaf node
  if (start == finish) {
    this->leaf = true;
    this->UpdateTreeLeafVector();
  }
}

BlockListNode::BlockListNode(int start, int finish, ZZ_p value,
                             std::weak_ptr<BlockListTree> treeptr) {
  this->value = value;
  this->tree = treeptr;
  this->parent = std::shared_ptr<BlockListNode>();
  this->start = start;
  this->finish = finish;
  this->leaf = false;
  this->leftchild = nullptr;
  this->rightchild = nullptr;

  // this is the condition for a leaf node
  if (start == finish) {
    this->leaf = true;
    this->UpdateTreeLeafVector();
  }
}

void BlockListNode::UpdateTreeLeafVector() {
  if (leaf) {
    if (std::shared_ptr<BlockListTree> treeptr = tree.lock()) {
      treeptr->leaves.push_back(GetValue());
    }
  }
};

// this is a recursive call
void BlockListNode::MakeChildren() {

  // TODO: calculate value;
  int halfwayoffset = (finish - start) / 2;
  ZZ_p leftv(value);
  ZZ_p rightv(value);

  // [start, finish] is index range that valuie did not exponentiate.
  //  exponentiate the value by the values in one half of the vector.
  //  rightchild didn't exponentiate the right half
  //  leftchild didn't exponentiate the left half
  //
  if (std::shared_ptr<BlockListTree> treeptr = tree.lock()) {
    for (int i = start; i <= (start + halfwayoffset); i++) {
      rightv = power(rightv, treeptr->blist.at(i));
    }

    for (int j = (start + halfwayoffset + 1); j <= finish; j++) {
      leftv = power(leftv, treeptr->blist.at(j));
    }
  }

  leftchild = std::make_shared<BlockListNode>(start, (start + halfwayoffset),
                                              leftv, tree, weak_from_this());
  rightchild = std::make_shared<BlockListNode>(
      (start + halfwayoffset + 1), finish, rightv, tree, weak_from_this());

  if (weak_from_this().expired() == true) {
    std::cerr << "MakeChildren has an issue" << std::endl;
  }
  // continue making children
  if (!leftchild->IsLeaf()) {
    leftchild->MakeChildren();
  }
  if (!rightchild->IsLeaf()) {
    rightchild->MakeChildren();
  }
};

bool BlockListNode::IsLeaf() { return leaf; }
ZZ_p BlockListNode::GetValue() { return value; }

BlockListTree::BlockListTree(const std::vector<ZZ> &blist, const ZZ_p &v,
                             const ZZ &N)
    : blist(blist), v(v), N(N) {
  this->leaves = std::vector<ZZ_p>();
}

void BlockListTree::BuildTree() {
  ZZ_p::init(N);
  try {
    this->root = std::make_shared<BlockListNode>(0, blist.size() - 1, v,
                                                 weak_from_this());
  } catch (std::bad_weak_ptr &e) {
    std::cerr << e.what() << std::endl;
  } catch (...) {
    std::cerr << "somthing else is going on" << std::endl;
  }

  if (weak_from_this().expired() == true) {
    std::cerr << "BuildTree has an issue" << std::endl;
  }

  this->root->MakeChildren();
}

// this feels a little round about
std::weak_ptr<BlockListTree> BlockListTree::getWeakptr() {
  return weak_from_this();
}

bool BlockListTree::IsBuilt() {
  return this->blist.size() == this->leaves.size();
}

std::shared_ptr<BlockListTree> BlockListTree::getptr() {
  return shared_from_this();
}

std::vector<ZZ_p> BlockListTree::GetLeafVector() { return this->leaves; }

std::vector<ZZ_p> MakeBlockListforClientInput(const std::vector<ZZ> &ZZvalues,
                                              const ZZ_p &v, const ZZ &N) {
  std::shared_ptr<BlockListTree> treeptr =
      std::make_shared<BlockListTree>(ZZvalues, v, N);
  auto test = treeptr->getptr();

  treeptr->BuildTree();
  return treeptr->GetLeafVector();
}

// I will want to know the number of lines in each file
// parsing a file would be very handy if there was fixed input length
// ths would allow me to do quick look up becuase I would know exactly which
// line to jump to
//
// I'm going to be naive and just loop to find where I want to go
// this still needs to be implemented
int getLinesInFile() { return 0; }
}; // namespace dynamicblocklist
