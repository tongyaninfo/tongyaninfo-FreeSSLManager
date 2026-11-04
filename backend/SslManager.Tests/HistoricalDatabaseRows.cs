using System.Data;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Data;

namespace SslManager.Tests;

/// <summary>历史迁移夹具只操作当时真实存在的列，避免未来模型字段使旧版本回归失效。</summary>
internal static class HistoricalDatabaseRows
{
    public static async Task InsertAsync<T>(AppDbContext db, string table, T row) where T : class
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open) await connection.OpenAsync();
        var names = new List<string>();
        await using (var schema = connection.CreateCommand())
        {
            schema.CommandText = $"PRAGMA table_info(\"{table}\")";
            await using var reader = await schema.ExecuteReaderAsync();
            while (await reader.ReadAsync()) names.Add(reader.GetString(1));
        }
        await using var command = connection.CreateCommand();
        var properties = names.Select(name => (Name: name, Property: typeof(T).GetProperty(name)))
            .Where(value => value.Property is not null).ToArray();
        command.CommandText = $"INSERT INTO \"{table}\" ({string.Join(',', properties.Select(x => $"\"{x.Name}\""))}) VALUES ({string.Join(',', properties.Select((_, index) => "$p" + index))})";
        for (var index = 0; index < properties.Length; index++)
        {
            var parameter = command.CreateParameter(); parameter.ParameterName = "$p" + index;
            parameter.Value = properties[index].Property!.GetValue(row) ?? DBNull.Value;
            command.Parameters.Add(parameter);
        }
        await command.ExecuteNonQueryAsync();
    }

    public static async Task<string> ScalarAsync(AppDbContext db, string sql)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open) await connection.OpenAsync();
        await using var command = connection.CreateCommand(); command.CommandText = sql;
        return Convert.ToString(await command.ExecuteScalarAsync()) ?? "";
    }
}
