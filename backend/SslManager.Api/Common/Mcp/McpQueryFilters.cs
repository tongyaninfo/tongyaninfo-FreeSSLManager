using System.Linq.Expressions;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>把每条规则的适用资源条件作为交集，再把规则取并集，先过滤 SQL 再统计和分页。</summary>
public static class McpQueryFilters
{
    public static Expression<Func<T, bool>> Build<T>(IEnumerable<McpAllowRuleInput> rules,
        Expression<Func<T, string>>? account = null, Expression<Func<T, string>>? domain = null,
        Expression<Func<T, string>>? target = null)
    {
        var parameter = Expression.Parameter(typeof(T), "item");
        Expression allowed = Expression.Constant(false);
        foreach (var rule in rules)
        {
            Expression match = Expression.Constant(true);
            if (account is not null) match = Expression.AndAlso(match, Ids(Body(account, parameter), rule.AccountIds, rule.AllAccounts));
            if (domain is not null) match = Expression.AndAlso(match, Domain(Body(domain, parameter), rule.Domains, rule.AllDomains));
            if (target is not null) match = Expression.AndAlso(match, Ids(Body(target, parameter), rule.TargetIds, rule.AllTargets));
            allowed = Expression.OrElse(allowed, match);
        }
        return Expression.Lambda<Func<T, bool>>(allowed, parameter);
    }

    public static Expression<Func<T, bool>> Or<T>(Expression<Func<T, bool>> left, Expression<Func<T, bool>> right)
    {
        var parameter = left.Parameters[0];
        return Expression.Lambda<Func<T, bool>>(Expression.OrElse(left.Body, new Replace(right.Parameters[0], parameter).Visit(right.Body)!), parameter);
    }

    public static bool DomainMatches(string value, McpAllowRuleInput rule)
    {
        var domain = NormalizeDomain(value);
        return rule.AllDomains || rule.Domains.Any(pattern => Match(domain, NormalizeDomain(pattern)));
    }

    public static string NormalizeDomain(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static bool Match(string domain, string pattern) => pattern.StartsWith("*.", StringComparison.Ordinal)
        ? domain.EndsWith(pattern[1..], StringComparison.Ordinal) && domain.Length > pattern.Length - 1
        : domain == pattern;

    private static Expression Domain(Expression value, string[] patterns, bool all)
    {
        if (all) return Expression.Constant(true);
        Expression match = Expression.Constant(false);
        // 域名在业务入库时已规范化；ToLower 可由 SQLite 翻译，避免在内存分页后再遮蔽数据。
        var lower = Expression.Call(value, nameof(string.ToLower), Type.EmptyTypes);
        foreach (var raw in patterns)
        {
            var pattern = NormalizeDomain(raw);
            Expression item = pattern.StartsWith("*.", StringComparison.Ordinal)
                ? Expression.Call(lower, nameof(string.EndsWith), Type.EmptyTypes, Expression.Constant(pattern[1..]))
                : Expression.Equal(lower, Expression.Constant(pattern));
            match = Expression.OrElse(match, item);
        }
        return match;
    }
    private static Expression Ids(Expression value, string[] ids, bool all) => all ? Expression.Constant(true)
        : Expression.Call(typeof(Enumerable), nameof(Enumerable.Contains), [typeof(string)], Expression.Constant(ids), value);
    private static Expression Body<T>(Expression<Func<T, string>> expression, ParameterExpression parameter) => new Replace(expression.Parameters[0], parameter).Visit(expression.Body)!;
    private sealed class Replace(ParameterExpression source, ParameterExpression target) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == source ? target : node;
    }
}
