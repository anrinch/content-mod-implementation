#ifndef DYNAMIC_BLOCKLIST_HPP
#define DYNAMIC_BLOCKLIST_HPP

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <memory>
#include <vector>

using NTL::ZZ;
using NTL::ZZ_p;
using std::shared_ptr;
using std::vector;

// input <-vector of ZZ values
// at this point, the values have been through H_p
// Sort the nodes
// I will want to sort my vector by position
// I can use a lambda funciton to do that

// be sure that is owned by a shared pointer

namespace dynamicblocklist {

class BlockListTree;

class BlockListNode : public std::enable_shared_from_this<BlockListNode> {
  friend class dynamicblocklist::BlockListTree;

public:
  BlockListNode(int start, int finish, ZZ_p value,
                std::weak_ptr<BlockListTree> treeptr);
  BlockListNode(int start, int finish, ZZ_p value,
                std::weak_ptr<BlockListTree> treeptr,
                std::weak_ptr<BlockListNode> parentptr);
  void UpdateTreeLeafVector();
  void MakeChildren();
  bool IsLeaf();
  ZZ_p GetValue();

private:
  // if something is a leaf, then this will be populated
  bool leaf;

  // this for children nodes, left and right child will be nullptrs
  std::shared_ptr<BlockListNode> leftchild;
  std::shared_ptr<BlockListNode> rightchild;

  // every node will have a parent and belong to a BlockListTree
  ZZ_p value;
  std::weak_ptr<BlockListNode> parent;
  std::weak_ptr<BlockListTree> tree;
  int start;
  int finish;
};

// This should reduce the matching caclculation to be from n^2 to n log n
// if its a leaf node, then it should have the value we're looking for
class BlockListTree : public std::enable_shared_from_this<BlockListTree> {
  friend class BlockListNode;

public:
  BlockListTree(const std::vector<ZZ> &blist, const ZZ_p &v, const ZZ &N);
  void BuildTree();
  bool IsBuilt();
  std::vector<ZZ_p> GetLeafVector();
  std::weak_ptr<BlockListTree> getWeakptr();
  std::shared_ptr<BlockListTree> getptr();

private:
  const std::vector<ZZ> blist;
  bool built;
  std::shared_ptr<BlockListNode> root;
  std::vector<ZZ_p> leaves;
  const ZZ N;
  // this the Z' value that was being talked about SHI-PSI
  const ZZ_p v;
};

// TODO: I may need to come up with a clever way to scale this. Might be a
// week's worth of work
std::vector<ZZ_p> MakeBlockListforClientInput(const std::vector<ZZ> &ZZvalues,
                                              const ZZ_p &v, const ZZ &N);
}; // namespace dynamicblocklist
#endif
