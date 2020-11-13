#include "clang/Basic/LangOptions.h"
#include "clang/Basic/LLVM.h"
#include "clang/Basic/SourceManager.h"
#include "clang/AST/AST.h"
#include "clang/AST/DeclObjC.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/EvaluatedExprVisitor.h"

#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Analysis/CFG.h"
#include "clang/Driver/Options.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Option/OptTable.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Path.h"
// #include "llvm/Support/CommandLine.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;
using namespace llvm;

static llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp("No more help");

// static cl::OptionCategory ClangCheckCategory("clang-print-functions options")
static const opt::OptTable &Options = getDriverOptTable();

class MyEvaluatedExprVisitor : public EvaluatedExprVisitor<MyEvaluatedExprVisitor> {
  public:
    explicit MyEvaluatedExprVisitor(ASTContext &C, Rewriter &R) : EvaluatedExprVisitor(C), TheContext(C), TheRewriter(R) {}
    virtual ~MyEvaluatedExprVisitor() {}
    
    // virtual void VisitAbstractConditionalOperator(){}
    virtual void VisitBinaryOperator(BinaryOperator *bo){
      bo->dump();
    }
    // virtual void VisitUnaryOperator(){}
    // virtual void VisitBinaryConditionalOperator(){};
    // virtual void VisitCompoundAssignOperator(){};
    // virtual void VisitConditionOperator(){};

    void VisitDeclRefExpr(DeclRefExpr *dr) {
      dr->dump();
    }

  private:
    ASTContext &TheContext;
    Rewriter &TheRewriter;
};


class MyRecurisveASTVisitor : public RecursiveASTVisitor<MyRecurisveASTVisitor> {
  public:
    MyRecurisveASTVisitor(ASTContext &C, Rewriter &R) : TheContext(C), TheRewriter(R), evalVisitor(C, R) {}
    bool VisitFunctionDecl(FunctionDecl *f) {
      if (f->hasBody()) {
        Stmt *fb = f->getBody();
        // evalVisitor.VisitStmt(fb);
        std::unique_ptr<CFG> cfg = CFG::buildCFG(f, fb, &TheContext, CFG::BuildOptions());
        cfg->viewCFG(LangOptions());
        CFGBlock *blk = cfg->getIndirectGotoBlock();
        if (blk)
          blk->dump();
        cfg->dump(LangOptions(), true);
      }
      return true;
    }

  private:
    ASTContext &TheContext;
    Rewriter &TheRewriter;
    MyEvaluatedExprVisitor evalVisitor;
};

class MyASTConsumer : public ASTConsumer
{
public:
  MyASTConsumer(ASTContext &C, Rewriter &R) : astVisitor(C, R) {}
  bool HandleTopLevelDecl(DeclGroupRef DR) override {
    for (DeclGroupRef::iterator b = DR.begin(), e =  DR.end(); b != e; ++b) {
      astVisitor.TraverseDecl(*b);
    }
    return true;
  }
private:
  MyRecurisveASTVisitor astVisitor;
};

class MyFrontendAction : public ASTFrontendAction {
  public:
    MyFrontendAction() {}
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
      TheRewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
      std::unique_ptr<MyASTConsumer> v = std::make_unique<MyASTConsumer>(CI.getASTContext(), TheRewriter);
      return v;
    }
  private:
    Rewriter TheRewriter;
};

int main(int argc, const char **argv) {

  CommonOptionsParser op(argc, argv, ToolingSampleCategory);
  
  ClangTool Tool(op.getCompilations(), op.getSourcePathList());
  return Tool.run(newFrontendActionFactory<MyFrontendAction>().get());
}
